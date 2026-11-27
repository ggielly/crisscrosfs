//! POSIX → Windows security descriptor mapping.
//!
//! XFS stores Unix `mode`/`uid`/`gid`, while WinFsp expects a self-relative
//! Windows security descriptor.  There is no general uid/gid → Windows account
//! directory on Windows, so identities are mapped explicitly:
//!
//! * uid 0 → the account that mounted a writable volume, or `NT
//!   AUTHORITY\SYSTEM` for read-only volumes
//! * gid 0 → `BUILTIN\Administrators`
//! * other ids → only SIDs listed in the optional `XFS_ACL_MAP` TOML file
//! * an unmapped uid produces an empty DACL (fail closed)
//!
//! Example `XFS_ACL_MAP` file:
//!
//! ```toml
//! [uids]
//! "1000" = "S-1-5-21-100-200-300-1001"
//! "1001" = "CURRENT_USER"
//!
//! [gids]
//! "1000" = "S-1-5-32-545"
//! ```
//!
//! POSIX selects exactly one class (owner, then group, then other), whereas a
//! Windows DACL would otherwise union every matching allow ACE.  Explicit deny
//! ACEs subtract group/other rights from the owner and other rights from the
//! group, reproducing POSIX class precedence for mapped identities.
//!
//! A writable image is owned by whoever mounted it: images are normally
//! created by root with 0755/0644 modes, and mapping uid 0 to `SYSTEM` would
//! leave the interactive user with the world bits only, i.e. a readable but
//! unwritable volume.  This mirrors the `-o uid=` behaviour of FUSE mounts.
//!
//! Read-only mounts never grant write or delete rights.  Sticky directories do
//! not receive `FILE_DELETE_CHILD`; setuid/setgid have no Windows ACL
//! equivalent and are intentionally ignored.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, MutexGuard},
};

use fs_abstraction::{types::VfsFileInfo, FsError};
use serde::Deserialize;
use xfs_rs::attr::{AclEntryTag, PosixAcl};

const SD_REVISION: u8 = 1;
const SID_REVISION: u8 = 1;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SELF_RELATIVE: u16 = 0x8000;
const ACL_REVISION: u8 = 2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// `FILE_GENERIC_READ`.
const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// `FILE_GENERIC_WRITE`.
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
/// `FILE_GENERIC_EXECUTE`.
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
/// `FILE_DELETE_CHILD`.
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
/// Specific write/delete bits, excluding standard rights shared with read and
/// execute masks.
#[cfg(test)]
const FILE_WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | FILE_DELETE_CHILD;

const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 8;
const SD_HEADER_SIZE: usize = 20;
const POSIX_STICKY: u32 = 0o1000;

/// Well-known SIDs, encoded in self-relative form.
fn sid(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + sub_authorities.len() * 4);
    bytes.push(SID_REVISION);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&authority);
    for id in sub_authorities {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

fn everyone_sid() -> Vec<u8> {
    // S-1-1-0
    sid([0, 0, 0, 0, 0, 1], &[0])
}

fn system_sid() -> Vec<u8> {
    // S-1-5-18
    sid([0, 0, 0, 0, 0, 5], &[18])
}

fn administrators_sid() -> Vec<u8> {
    // S-1-5-32-544
    sid([0, 0, 0, 0, 0, 5], &[32, 544])
}

fn valid_sid(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes[0] == SID_REVISION
        && bytes[1] <= 15
        && bytes.len() == 8 + usize::from(bytes[1]) * 4
}

/// Returns the SID of the user owning the current process.
///
/// This is only used when an ACL mapping explicitly contains
/// `"CURRENT_USER"`.  Failure is fail-closed: no mapping is installed.
#[cfg(windows)]
fn current_user_sid() -> Option<Vec<u8>> {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;

        let mut length: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut length);
        if length == 0 {
            let _ = CloseHandle(token);
            return None;
        }

        // Allocate aligned storage: TOKEN_USER contains pointers and must be
        // read through an aligned reference.  Vec<u8> does not guarantee this.
        let mut words = vec![0u64; (length as usize).div_ceil(std::mem::size_of::<u64>())];
        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(words.as_mut_ptr() as *mut std::ffi::c_void),
            length,
            &mut length,
        );
        let _ = CloseHandle(token);
        result.ok()?;

        let token_user = &*(words.as_ptr() as *const TOKEN_USER);
        let sid_ptr = token_user.User.Sid;
        let sid_len = GetLengthSid(sid_ptr) as usize;
        if sid_len == 0 {
            return None;
        }

        // Defensively ensure the SID returned by Windows lies inside the
        // token information buffer before copying it.
        let base = words.as_ptr() as usize;
        let sid_addr = sid_ptr.0 as usize;
        let sid_offset = sid_addr.checked_sub(base)?;
        sid_offset.checked_add(sid_len)?;
        if sid_offset + sid_len > length as usize {
            return None;
        }

        Some(std::slice::from_raw_parts(sid_ptr.0 as *const u8, sid_len).to_vec())
    }
}

#[cfg(not(windows))]
fn current_user_sid() -> Option<Vec<u8>> {
    None
}

/// Converts an SDDL SID string (for example `S-1-5-32-545`) to bytes.
#[cfg(windows)]
fn sid_from_string(text: &str) -> Option<Vec<u8>> {
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::{Authorization::ConvertStringSidToSidW, GetLengthSid, PSID},
        },
    };

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut sid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid).ok()?;
        let len = GetLengthSid(sid) as usize;
        if len == 0 {
            LocalFree(HLOCAL(sid.0));
            return None;
        }
        let bytes = std::slice::from_raw_parts(sid.0 as *const u8, len).to_vec();
        LocalFree(HLOCAL(sid.0));
        Some(bytes)
    }
}

#[cfg(not(windows))]
fn sid_from_string(_text: &str) -> Option<Vec<u8>> {
    None
}

#[derive(Debug, Default, Deserialize)]
struct AclConfig {
    #[serde(default)]
    uids: BTreeMap<String, String>,
    #[serde(default)]
    gids: BTreeMap<String, String>,
}

fn load_acl_config() -> Option<AclConfig> {
    let path = std::env::var_os("XFS_ACL_MAP")?;
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            tracing::warn!(%error, "Cannot read XFS_ACL_MAP; using fail-closed root-only mapping");
            return None;
        }
    };

    match toml::from_str::<AclConfig>(&contents) {
        Ok(config) => Some(config),
        Err(error) => {
            tracing::warn!(%error, "Invalid XFS_ACL_MAP; using fail-closed root-only mapping");
            None
        }
    }
}

fn apply_config_map(
    values: BTreeMap<String, String>,
    target: &mut BTreeMap<u32, Vec<u8>>,
    current_user: Option<&[u8]>,
    kind: &str,
) {
    for (id, value) in values {
        let Ok(id) = id.parse::<u32>() else {
            tracing::warn!(kind, value = %id, "Ignoring non-numeric ACL mapping id");
            continue;
        };

        let sid = if value.eq_ignore_ascii_case("CURRENT_USER") {
            current_user.map(<[u8]>::to_vec)
        } else {
            sid_from_string(&value)
        };

        match sid {
            Some(sid) => {
                target.insert(id, sid);
            }
            None => tracing::warn!(kind, value = %value, "Ignoring unmappable ACL SID"),
        }
    }
}

/// Translates a POSIX permission triad into Windows access rights.
fn rights_for(mode: u32, mode_bits: u8, is_directory: bool, read_only: bool) -> u32 {
    let mut rights = 0u32;
    if mode_bits & 0b100 != 0 {
        rights |= FILE_GENERIC_READ;
    }
    if mode_bits & 0b010 != 0 && !read_only {
        rights |= FILE_GENERIC_WRITE;
        // A sticky directory may create entries but must not grant blanket
        // deletion of other users' entries.  A faithful per-entry sticky check
        // would require the caller identity and is deferred until write support
        // is implemented; omitting FILE_DELETE_CHILD is the conservative rule.
        if is_directory && (mode & POSIX_STICKY) == 0 {
            rights |= FILE_DELETE_CHILD;
        }
    }
    if mode_bits & 0b001 != 0 {
        rights |= FILE_GENERIC_EXECUTE;
    }
    rights
}

/// Builds a self-relative security descriptor with a protected DACL.
///
/// `aces` contains `(ace_type, mask, sid)` tuples.
fn build_security_descriptor(owner: &[u8], group: &[u8], aces: &[(u8, u32, &[u8])]) -> Vec<u8> {
    let acl_len = ACL_HEADER_SIZE
        + aces
            .iter()
            .map(|(_, _, sid)| ACE_HEADER_SIZE + sid.len())
            .sum::<usize>();
    let mut acl = Vec::with_capacity(acl_len);
    acl.push(ACL_REVISION);
    acl.push(0); // Sbz1
    acl.extend_from_slice(&(acl_len as u16).to_le_bytes());
    acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    acl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2

    for (ace_type, mask, sid) in aces {
        acl.push(*ace_type);
        acl.push(0); // AceFlags
        acl.extend_from_slice(&((ACE_HEADER_SIZE + sid.len()) as u16).to_le_bytes());
        acl.extend_from_slice(&mask.to_le_bytes());
        acl.extend_from_slice(sid);
    }

    let owner_offset = SD_HEADER_SIZE;
    let group_offset = owner_offset + owner.len();
    let dacl_offset = group_offset + group.len();

    let mut sd = Vec::with_capacity(dacl_offset + acl.len());
    sd.push(SD_REVISION);
    sd.push(0); // Sbz1
    sd.extend_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED).to_le_bytes());
    sd.extend_from_slice(&(owner_offset as u32).to_le_bytes());
    sd.extend_from_slice(&(group_offset as u32).to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // no SACL
    sd.extend_from_slice(&(dacl_offset as u32).to_le_bytes());
    sd.extend_from_slice(owner);
    sd.extend_from_slice(group);
    sd.extend_from_slice(&acl);
    sd
}

type DescriptorKey = (u32, u32, u32, Option<Arc<[u8]>>);
type SharedDescriptor = Arc<[u8]>;
type DescriptorCache = HashMap<DescriptorKey, SharedDescriptor>;

/// Builds security descriptors for XFS inode metadata.
pub struct AclMapper {
    read_only: bool,
    uid_map: BTreeMap<u32, Vec<u8>>,
    gid_map: BTreeMap<u32, Vec<u8>>,
    everyone_sid: Vec<u8>,
    system_sid: Vec<u8>,
    administrators_sid: Vec<u8>,
    descriptors: Mutex<DescriptorCache>,
}

impl AclMapper {
    /// Creates a mapper from `XFS_ACL_MAP` (if set).
    ///
    /// Root is always mapped.  Non-root ids are only granted access through
    /// explicit mappings; token lookup failure therefore cannot broaden access.
    pub fn new(read_only: bool) -> Self {
        let current_user = current_user_sid();

        // Ownership of the volume follows the mount: root-owned inodes are
        // attributed to the account performing a writable mount so it gets the
        // POSIX owner class, and to SYSTEM for read-only mounts (which cannot
        // write anyway) or when the token lookup fails.
        let root_sid = if read_only {
            system_sid()
        } else {
            current_user.clone().unwrap_or_else(system_sid)
        };

        let mut uid_map = BTreeMap::from([(0, root_sid)]);
        let mut gid_map = BTreeMap::from([(0, administrators_sid())]);

        if let Some(config) = load_acl_config() {
            apply_config_map(config.uids, &mut uid_map, current_user.as_deref(), "uid");
            apply_config_map(config.gids, &mut gid_map, current_user.as_deref(), "gid");
        }

        Self {
            read_only,
            uid_map,
            gid_map,
            everyone_sid: everyone_sid(),
            system_sid: system_sid(),
            administrators_sid: administrators_sid(),
            descriptors: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a deterministic mapper with explicit additional UID/GID maps.
    /// Root mappings are included automatically and may be overridden.
    pub fn with_mappings(
        read_only: bool,
        uid_map: BTreeMap<u32, Vec<u8>>,
        gid_map: BTreeMap<u32, Vec<u8>>,
    ) -> Self {
        let mut uid_map = uid_map;
        let mut gid_map = gid_map;
        uid_map.retain(|_, sid| valid_sid(sid));
        gid_map.retain(|_, sid| valid_sid(sid));
        uid_map.entry(0).or_insert_with(system_sid);
        gid_map.entry(0).or_insert_with(administrators_sid);

        Self {
            read_only,
            uid_map,
            gid_map,
            everyone_sid: everyone_sid(),
            system_sid: system_sid(),
            administrators_sid: administrators_sid(),
            descriptors: Mutex::new(HashMap::new()),
        }
    }

    /// Builds the self-relative security descriptor for `info`.
    ///
    /// Descriptors are immutable and shared by files with equivalent mode,
    /// ownership, and access-ACL bytes. Default ACLs do not affect the current
    /// file's descriptor and are therefore not part of the cache key.
    pub fn security_descriptor(&self, info: &VfsFileInfo) -> Arc<[u8]> {
        let access_acl = info
            .posix_acl
            .as_ref()
            .and_then(|acl| acl.access.as_ref())
            .cloned();
        let key = (info.mode, info.uid, info.gid, access_acl);
        if let Some(cached) = self.descriptors().get(&key).cloned() {
            return cached;
        }
        let descriptor: Arc<[u8]> = self.build_security_descriptor(info).into();
        self.descriptors()
            .entry(key)
            .or_insert_with(|| descriptor.clone())
            .clone()
    }

    fn descriptors(&self) -> MutexGuard<'_, DescriptorCache> {
        self.descriptors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn build_security_descriptor(&self, info: &VfsFileInfo) -> Vec<u8> {
        if let Some(raw_acl) = info.posix_acl.as_ref().and_then(|acl| acl.access.as_ref()) {
            return self.build_acl_descriptor(info, raw_acl);
        }
        self.build_mode_descriptor(info)
    }

    fn empty_descriptor(&self) -> Vec<u8> {
        build_security_descriptor(&self.system_sid, &self.administrators_sid, &[])
    }

    fn build_acl_descriptor(&self, info: &VfsFileInfo, raw_acl: &[u8]) -> Vec<u8> {
        let acl = match PosixAcl::parse(raw_acl) {
            Ok(acl) => acl,
            Err(error) => {
                tracing::warn!(ino = info.ino, %error, "Ignoring malformed POSIX ACL; denying access");
                return self.empty_descriptor();
            }
        };
        let Some(owner_sid) = self.uid_map.get(&info.uid) else {
            return self.empty_descriptor();
        };
        let Some(group_obj_sid) = self.gid_map.get(&info.gid) else {
            // An unmapped ACL identity cannot be represented faithfully. In
            // particular, omitting it would let Everyone grant the other class.
            return self.empty_descriptor();
        };

        let mut owner_permissions = 0u8;
        let mut group_obj_permissions = 0u8;
        let mut other_permissions = 0u8;
        let mut mask = None;
        let mut named_users = Vec::new();
        let mut named_groups = Vec::new();
        for entry in acl.entries() {
            match entry.tag {
                AclEntryTag::UserObj => owner_permissions = entry.perm,
                AclEntryTag::GroupObj => group_obj_permissions = entry.perm,
                AclEntryTag::Other => other_permissions = entry.perm,
                AclEntryTag::Mask => mask = Some(entry.perm),
                AclEntryTag::User => named_users.push((entry.id, entry.perm)),
                AclEntryTag::Group => named_groups.push((entry.id, entry.perm)),
            }
        }
        let mask = mask.unwrap_or(0b111);
        let is_directory = info.is_dir();

        let mut users_by_sid: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
        for (uid, permissions) in named_users {
            let Some(sid) = self.uid_map.get(&uid) else {
                return self.empty_descriptor();
            };
            let rights = rights_for(info.mode, permissions & mask, is_directory, self.read_only);
            *users_by_sid.entry(sid.clone()).or_default() |= rights;
        }

        let mut groups_by_sid: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
        let group_obj_rights = rights_for(
            info.mode,
            group_obj_permissions & mask,
            is_directory,
            self.read_only,
        );
        *groups_by_sid.entry(group_obj_sid.clone()).or_default() |= group_obj_rights;
        for (gid, permissions) in named_groups {
            let Some(sid) = self.gid_map.get(&gid) else {
                return self.empty_descriptor();
            };
            let rights = rights_for(info.mode, permissions & mask, is_directory, self.read_only);
            *groups_by_sid.entry(sid.clone()).or_default() |= rights;
        }

        let owner_rights = rights_for(info.mode, owner_permissions, is_directory, self.read_only);
        let other_rights = rights_for(info.mode, other_permissions, is_directory, self.read_only);
        let all_user_rights = users_by_sid
            .values()
            .fold(0u32, |rights, entry| rights | *entry);
        let all_group_rights = groups_by_sid
            .values()
            .fold(0u32, |rights, entry| rights | *entry);

        // Windows unions matching allow ACEs. Compute the single POSIX class
        // that wins for each mapped SID, then emit explicit denies for rights
        // offered by lower-priority classes. All denies precede all allows.
        let mut effective: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
        let mut denies: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
        effective.insert(owner_sid.clone(), owner_rights);
        *denies.entry(owner_sid.clone()).or_default() |=
            (all_user_rights | all_group_rights | other_rights) & !owner_rights;

        for (sid, rights) in &users_by_sid {
            if sid != owner_sid {
                *effective.entry(sid.clone()).or_default() |= *rights;
                *denies.entry(sid.clone()).or_default() |=
                    (all_group_rights | other_rights) & !*rights;
            }
        }
        for (sid, rights) in &groups_by_sid {
            if sid != owner_sid && !users_by_sid.contains_key(sid) {
                *effective.entry(sid.clone()).or_default() |= *rights;
                *denies.entry(sid.clone()).or_default() |= other_rights & !*rights;
            }
        }

        let mut aces: Vec<(u8, u32, &[u8])> =
            Vec::with_capacity(denies.len() + effective.len() + usize::from(other_rights != 0));
        for (sid, rights) in &denies {
            if *rights != 0 {
                aces.push((ACCESS_DENIED_ACE_TYPE, *rights, sid.as_slice()));
            }
        }
        for (sid, rights) in &effective {
            if *rights != 0 {
                aces.push((ACCESS_ALLOWED_ACE_TYPE, *rights, sid.as_slice()));
            }
        }
        if other_rights != 0 {
            aces.push((ACCESS_ALLOWED_ACE_TYPE, other_rights, &self.everyone_sid));
        }

        // Windows stores ACL and ACE sizes in 16-bit fields. A valid POSIX
        // ACL can contain more entries than fit in one DACL; deny access rather
        // than emitting a truncated or otherwise invalid descriptor.
        let Ok(acl_size) = aces.iter().try_fold(ACL_HEADER_SIZE, |size, (_, _, sid)| {
            size.checked_add(ACE_HEADER_SIZE)
                .ok_or(FsError::ArithmeticOverflow)?
                .checked_add(sid.len())
                .ok_or(FsError::ArithmeticOverflow)
        }) else {
            return self.empty_descriptor();
        };
        if u16::try_from(acl_size).is_err() {
            return self.empty_descriptor();
        }

        build_security_descriptor(owner_sid, group_obj_sid, aces.as_slice())
    }

    fn build_mode_descriptor(&self, info: &VfsFileInfo) -> Vec<u8> {
        let Some(owner_sid) = self.uid_map.get(&info.uid) else {
            // Without an owner mapping we cannot know which caller must use
            // the owner class instead of group/other.  Fail closed.
            return self.empty_descriptor();
        };

        let group_sid = self.gid_map.get(&info.gid);
        let is_directory = info.is_dir();
        let owner_bits = ((info.mode >> 6) & 0b111) as u8;
        let group_bits = ((info.mode >> 3) & 0b111) as u8;
        let other_bits = (info.mode & 0b111) as u8;

        let owner_rights = rights_for(info.mode, owner_bits, is_directory, self.read_only);
        let group_rights = group_sid
            .map(|_| rights_for(info.mode, group_bits, is_directory, self.read_only))
            .unwrap_or(0);
        let other_rights = rights_for(info.mode, other_bits, is_directory, self.read_only);

        let mut aces: Vec<(u8, u32, &[u8])> = Vec::with_capacity(5);

        // POSIX owner class wins over group/other. A matching deny ACE removes
        // any overlapping rights that Windows would otherwise union.
        let owner_deny = (group_rights | other_rights) & !owner_rights;
        if owner_deny != 0 {
            aces.push((ACCESS_DENIED_ACE_TYPE, owner_deny, owner_sid));
        }

        // POSIX group class wins over other. If owner and group map to the
        // same SID the owner deny above already implements owner precedence;
        // adding a group deny here would incorrectly remove owner rights.
        if let Some(group_sid) = group_sid {
            if group_sid != owner_sid {
                let group_deny = other_rights & !group_rights;
                if group_deny != 0 {
                    aces.push((ACCESS_DENIED_ACE_TYPE, group_deny, group_sid));
                }
            }
        }

        // Canonical DACL ordering requires every deny before any allow.
        if owner_rights != 0 {
            aces.push((ACCESS_ALLOWED_ACE_TYPE, owner_rights, owner_sid));
        }
        if group_rights != 0 {
            aces.push((ACCESS_ALLOWED_ACE_TYPE, group_rights, group_sid.unwrap()));
        }
        if other_rights != 0 {
            aces.push((ACCESS_ALLOWED_ACE_TYPE, other_rights, &self.everyone_sid));
        }

        build_security_descriptor(
            owner_sid,
            group_sid.unwrap_or(&self.administrators_sid),
            &aces,
        )
    }
}

#[cfg(test)]
mod tests {
    use fs_abstraction::types::{VfsFileType, VfsPosixAcl, VfsTimestamp};

    use super::*;

    fn info(mode: u32, uid: u32, gid: u32, file_type: VfsFileType) -> VfsFileInfo {
        VfsFileInfo {
            ino: 1,
            size: 0,
            blocks: 0,
            block_size: 4096,
            mode,
            file_type,
            nlink: 1,
            uid,
            gid,
            posix_acl: None,
            rdev: 0,
            atime: VfsTimestamp::default(),
            mtime: VfsTimestamp::default(),
            ctime: VfsTimestamp::default(),
            crtime: None,
        }
    }

    fn dacl_offset(sd: &[u8]) -> usize {
        u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize
    }

    fn acl_count(sd: &[u8]) -> u16 {
        let offset = dacl_offset(sd);
        u16::from_le_bytes(sd[offset + 4..offset + 6].try_into().unwrap())
    }

    fn ace_offset(sd: &[u8], index: usize) -> usize {
        let mut offset = dacl_offset(sd) + ACL_HEADER_SIZE;
        for _ in 0..index {
            let size = u16::from_le_bytes(sd[offset + 2..offset + 4].try_into().unwrap()) as usize;
            offset += size;
        }
        offset
    }

    fn ace_sid(sd: &[u8], index: usize) -> Vec<u8> {
        let offset = ace_offset(sd, index);
        let size = u16::from_le_bytes(sd[offset + 2..offset + 4].try_into().unwrap()) as usize;
        sd[offset + ACE_HEADER_SIZE..offset + size].to_vec()
    }

    fn ace_mask(sd: &[u8], index: usize) -> u32 {
        let offset = ace_offset(sd, index);
        u32::from_le_bytes(sd[offset + 4..offset + 8].try_into().unwrap())
    }

    fn ace_type(sd: &[u8], index: usize) -> u8 {
        sd[ace_offset(sd, index)]
    }

    fn sid_string(sid: &[u8]) -> String {
        let count = sid[1] as usize;
        let authority = sid[2..8]
            .iter()
            .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
        let mut parts = vec![format!("S-1-{}", authority)];
        for i in 0..count {
            let value = u32::from_le_bytes(sid[8 + i * 4..12 + i * 4].try_into().unwrap());
            parts.push(value.to_string());
        }
        parts.join("-")
    }

    fn root_mapper(read_only: bool) -> AclMapper {
        AclMapper::with_mappings(read_only, BTreeMap::new(), BTreeMap::new())
    }

    fn acl_bytes(entries: &[(AclEntryTag, u8, u32)]) -> Arc<[u8]> {
        let mut bytes = Vec::with_capacity(4 + entries.len() * 8);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        for &(tag, perm, id) in entries {
            bytes.extend_from_slice(&(tag as u16).to_le_bytes());
            bytes.extend_from_slice(&(perm as u16).to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes.into()
    }

    fn with_acl(mut info: VfsFileInfo, access: Arc<[u8]>) -> VfsFileInfo {
        info.posix_acl = Some(VfsPosixAcl {
            access: Some(access),
            default: None,
        });
        info
    }

    fn mapped_acl_mapper(read_only: bool) -> (AclMapper, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let owner = sid([0, 0, 0, 0, 0, 5], &[21, 1000]);
        let named_user = sid([0, 0, 0, 0, 0, 5], &[21, 1001]);
        let group = sid([0, 0, 0, 0, 0, 5], &[32, 1000]);
        let named_group = sid([0, 0, 0, 0, 0, 5], &[32, 1001]);
        let mapper = AclMapper::with_mappings(
            read_only,
            BTreeMap::from([(1000, owner.clone()), (1001, named_user.clone())]),
            BTreeMap::from([(1000, group.clone()), (1001, named_group.clone())]),
        );
        (mapper, owner, named_user, group, named_group)
    }

    fn ace_index(sd: &[u8], kind: u8, sid: &[u8]) -> Option<usize> {
        (0..acl_count(sd) as usize)
            .find(|&index| ace_type(sd, index) == kind && ace_sid(sd, index) == sid)
    }

    #[test]
    fn descriptor_is_self_relative_with_protected_dacl() {
        let sd =
            root_mapper(false).security_descriptor(&info(0o100644, 0, 0, VfsFileType::RegularFile));

        assert_eq!(sd[0], SD_REVISION);
        let control = u16::from_le_bytes(sd[2..4].try_into().unwrap());
        assert_eq!(
            control & (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED),
            0x9004
        );
        assert!(u32::from_le_bytes(sd[4..8].try_into().unwrap()) as usize >= SD_HEADER_SIZE);
        assert!(dacl_offset(&sd) >= SD_HEADER_SIZE);
        assert_eq!(acl_count(&sd), 3);
    }

    #[test]
    fn root_owner_maps_to_system_and_admin_group() {
        let sd =
            root_mapper(false).security_descriptor(&info(0o040755, 0, 0, VfsFileType::Directory));

        assert_eq!(sid_string(&ace_sid(&sd, 0)), "S-1-5-18");
        assert_eq!(sid_string(&ace_sid(&sd, 1)), "S-1-5-32-544");
        assert_eq!(sid_string(&ace_sid(&sd, 2)), "S-1-1-0");
        assert_ne!(ace_mask(&sd, 0) & FILE_DELETE_CHILD, 0);
    }

    #[test]
    fn identical_modes_share_one_security_descriptor() {
        let mapper = root_mapper(false);
        let first = mapper.security_descriptor(&info(0o100644, 0, 0, VfsFileType::RegularFile));
        let second = mapper.security_descriptor(&info(0o100644, 0, 0, VfsFileType::RegularFile));
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn different_access_acls_do_not_share_a_cached_descriptor() {
        let mapper = root_mapper(false);
        let base = info(0o100640, 0, 0, VfsFileType::RegularFile);
        let first_acl = acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::GroupObj, 4, u32::MAX),
            (AclEntryTag::Other, 0, u32::MAX),
        ]);
        let second_acl = acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::GroupObj, 4, u32::MAX),
            (AclEntryTag::Other, 4, u32::MAX),
        ]);
        let first_info = with_acl(base.clone(), first_acl.clone());
        let second_info = with_acl(base.clone(), second_acl);
        let first = mapper.security_descriptor(&first_info);
        let second = mapper.security_descriptor(&second_info);

        assert!(!Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(
            &first,
            &mapper.security_descriptor(&with_acl(base, first_acl))
        ));
    }

    #[test]
    fn acl_mask_caps_named_users_and_groups_but_not_owner_or_other() {
        let (mapper, owner, named_user, group, named_group) = mapped_acl_mapper(false);
        let raw = acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::User, 7, 1001),
            (AclEntryTag::GroupObj, 7, u32::MAX),
            (AclEntryTag::Group, 5, 1001),
            (AclEntryTag::Mask, 4, u32::MAX),
            (AclEntryTag::Other, 1, u32::MAX),
        ]);
        PosixAcl::parse(&raw).unwrap();
        let sd = mapper.security_descriptor(&with_acl(
            info(0o100640, 1000, 1000, VfsFileType::RegularFile),
            raw,
        ));
        assert_eq!(acl_count(&sd), 9);

        let user_index = ace_index(&sd, ACCESS_ALLOWED_ACE_TYPE, &named_user).unwrap();
        let group_index = ace_index(&sd, ACCESS_ALLOWED_ACE_TYPE, &group).unwrap();
        let named_group_index = ace_index(&sd, ACCESS_ALLOWED_ACE_TYPE, &named_group).unwrap();
        assert_eq!(ace_mask(&sd, user_index), FILE_GENERIC_READ);
        assert_eq!(ace_mask(&sd, group_index), FILE_GENERIC_READ);
        assert_eq!(ace_mask(&sd, named_group_index), FILE_GENERIC_READ);

        let owner_index = ace_index(&sd, ACCESS_ALLOWED_ACE_TYPE, &owner).unwrap();
        assert_ne!(ace_mask(&sd, owner_index) & FILE_GENERIC_WRITE, 0);
        assert_eq!(
            ace_mask(&sd, owner_index)
                & (FILE_GENERIC_EXECUTE & !(FILE_GENERIC_READ | FILE_GENERIC_WRITE)),
            0
        );
        let everyone_index = ace_index(&sd, ACCESS_ALLOWED_ACE_TYPE, &everyone_sid()).unwrap();
        assert_eq!(ace_mask(&sd, everyone_index), FILE_GENERIC_EXECUTE);

        let mut saw_allow = false;
        for index in 0..acl_count(&sd) as usize {
            if ace_type(&sd, index) == ACCESS_ALLOWED_ACE_TYPE {
                saw_allow = true;
            } else {
                assert!(!saw_allow, "all deny ACEs must precede allow ACEs");
            }
        }
    }

    #[test]
    fn named_user_class_wins_when_user_and_group_map_to_the_same_sid() {
        let owner = sid([0, 0, 0, 0, 0, 5], &[21, 1000]);
        let shared = sid([0, 0, 0, 0, 0, 5], &[21, 2000]);
        let group = sid([0, 0, 0, 0, 0, 5], &[32, 1000]);
        let mapper = AclMapper::with_mappings(
            false,
            BTreeMap::from([(1000, owner.clone()), (2000, shared.clone())]),
            BTreeMap::from([(1000, group), (2000, shared.clone())]),
        );
        let raw = acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::User, 4, 2000),
            (AclEntryTag::GroupObj, 0, u32::MAX),
            (AclEntryTag::Group, 6, 2000),
            (AclEntryTag::Mask, 7, u32::MAX),
            (AclEntryTag::Other, 1, u32::MAX),
        ]);
        let sd = mapper.security_descriptor(&with_acl(
            info(0o100600, 1000, 1000, VfsFileType::RegularFile),
            raw,
        ));

        let allow = ace_index(&sd, ACCESS_ALLOWED_ACE_TYPE, &shared).unwrap();
        assert_eq!(ace_mask(&sd, allow), FILE_GENERIC_READ);
        let deny = ace_index(&sd, ACCESS_DENIED_ACE_TYPE, &shared).unwrap();
        assert_ne!(ace_mask(&sd, deny) & FILE_GENERIC_WRITE, 0);
        assert_ne!(ace_mask(&sd, deny) & FILE_GENERIC_EXECUTE, 0);
    }

    #[test]
    fn malformed_or_unmapped_access_acls_fail_closed_without_mode_fallback() {
        let mapper = root_mapper(false);
        let base = info(0o100644, 0, 0, VfsFileType::RegularFile);
        let malformed = Arc::from([0u8, 0, 0, 0].as_slice());
        assert_eq!(
            acl_count(&mapper.security_descriptor(&with_acl(base.clone(), malformed))),
            0
        );

        let unmapped_named_user = acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::User, 4, 1000),
            (AclEntryTag::GroupObj, 4, u32::MAX),
            (AclEntryTag::Mask, 4, u32::MAX),
            (AclEntryTag::Other, 4, u32::MAX),
        ]);
        assert_eq!(
            acl_count(&mapper.security_descriptor(&with_acl(base, unmapped_named_user))),
            0
        );
    }

    #[test]
    fn invalid_sid_mappings_and_oversized_acls_fail_closed() {
        let invalid_mapper = AclMapper::with_mappings(
            false,
            BTreeMap::from([(1000, Vec::new())]),
            BTreeMap::from([(1000, sid([0, 0, 0, 0, 0, 5], &[32, 1000]))]),
        );
        assert_eq!(
            acl_count(&invalid_mapper.security_descriptor(&info(
                0o100644,
                1000,
                1000,
                VfsFileType::RegularFile,
            ))),
            0
        );

        let mut uid_map = BTreeMap::new();
        let mut entries = vec![(AclEntryTag::UserObj, 0, u32::MAX)];
        for id in 1..=3500 {
            uid_map.insert(id, sid([0, 0, 0, 0, 0, 5], &[21, id]));
            entries.push((AclEntryTag::User, 4, id));
        }
        entries.push((AclEntryTag::GroupObj, 0, u32::MAX));
        entries.push((AclEntryTag::Mask, 7, u32::MAX));
        entries.push((AclEntryTag::Other, 0, u32::MAX));
        let mapper = AclMapper::with_mappings(false, uid_map, BTreeMap::new());
        let sd = mapper.security_descriptor(&with_acl(
            info(0o100600, 0, 0, VfsFileType::RegularFile),
            acl_bytes(&entries),
        ));
        assert_eq!(acl_count(&sd), 0);
    }

    #[test]
    fn read_only_mount_strips_write_and_delete_from_acl_rights() {
        let raw = acl_bytes(&[
            (AclEntryTag::UserObj, 7, u32::MAX),
            (AclEntryTag::GroupObj, 7, u32::MAX),
            (AclEntryTag::Mask, 7, u32::MAX),
            (AclEntryTag::Other, 7, u32::MAX),
        ]);
        let sd = root_mapper(true)
            .security_descriptor(&with_acl(info(0o040777, 0, 0, VfsFileType::Directory), raw));
        for index in 0..acl_count(&sd) as usize {
            assert_eq!(ace_mask(&sd, index) & FILE_WRITE_RIGHTS, 0);
        }
    }

    #[test]
    fn other_bits_map_to_everyone() {
        let sd =
            root_mapper(false).security_descriptor(&info(0o100004, 0, 0, VfsFileType::RegularFile));

        assert_eq!(acl_count(&sd), 3);
        // Owner and group must not inherit the "other" class. Denies come
        // first.
        assert_eq!(ace_type(&sd, 0), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 0)), "S-1-5-18");
        assert_eq!(ace_type(&sd, 1), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 1)), "S-1-5-32-544");
        assert_eq!(ace_type(&sd, 2), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 2)), "S-1-1-0");
        assert_eq!(ace_mask(&sd, 2), FILE_GENERIC_READ);
    }

    #[test]
    fn zero_mode_produces_empty_dacl() {
        let sd =
            root_mapper(false).security_descriptor(&info(0o100000, 0, 0, VfsFileType::RegularFile));
        assert_eq!(acl_count(&sd), 0);
    }

    #[test]
    fn unmapped_uid_fails_closed() {
        let sd = root_mapper(false).security_descriptor(&info(
            0o100644,
            1000,
            1000,
            VfsFileType::RegularFile,
        ));
        assert_eq!(acl_count(&sd), 0);
    }

    #[test]
    fn owner_class_denies_group_and_other_rights() {
        let owner = sid([0, 0, 0, 0, 0, 5], &[21, 1000]);
        let group = sid([0, 0, 0, 0, 0, 5], &[32, 1000]);
        let mapper = AclMapper::with_mappings(
            false,
            BTreeMap::from([(1000, owner.clone())]),
            BTreeMap::from([(1000, group.clone())]),
        );
        let sd = mapper.security_descriptor(&info(
            0o100204, // owner write, other read
            1000,
            1000,
            VfsFileType::RegularFile,
        ));

        assert_eq!(acl_count(&sd), 4);
        assert_eq!(ace_type(&sd, 0), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 0), owner);
        assert_eq!(ace_mask(&sd, 0), FILE_GENERIC_READ & !FILE_GENERIC_WRITE);
        assert_eq!(ace_type(&sd, 1), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 1), group);
        assert_eq!(ace_mask(&sd, 1), FILE_GENERIC_READ);
        assert_eq!(ace_type(&sd, 2), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 2), owner);
        assert_eq!(ace_type(&sd, 3), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 3)), "S-1-1-0");
    }

    #[test]
    fn group_class_denies_other_rights() {
        let owner = sid([0, 0, 0, 0, 0, 5], &[21, 1000]);
        let group = sid([0, 0, 0, 0, 0, 5], &[32, 1000]);
        let mapper = AclMapper::with_mappings(
            false,
            BTreeMap::from([(1000, owner.clone())]),
            BTreeMap::from([(1000, group.clone())]),
        );
        let sd = mapper.security_descriptor(&info(
            0o100041, // group read, other execute
            1000,
            1000,
            VfsFileType::RegularFile,
        ));

        assert_eq!(acl_count(&sd), 4);
        assert_eq!(ace_type(&sd, 0), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 0), owner);
        assert_eq!(
            ace_mask(&sd, 0) & FILE_GENERIC_EXECUTE,
            FILE_GENERIC_EXECUTE
        );
        assert_eq!(ace_type(&sd, 1), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 1), group);
        assert_eq!(ace_mask(&sd, 1), FILE_GENERIC_EXECUTE & !FILE_GENERIC_READ);
        assert_eq!(ace_type(&sd, 2), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 2), group);
        assert_eq!(ace_type(&sd, 3), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 3)), "S-1-1-0");
    }

    fn owner_sid(sd: &[u8]) -> Vec<u8> {
        let offset = u32::from_le_bytes([sd[4], sd[5], sd[6], sd[7]]) as usize;
        let length = sd[offset + 1] as usize * 4 + 8;
        sd[offset..offset + length].to_vec()
    }

    #[test]
    fn writable_mounts_attribute_root_inodes_to_the_mounting_account() {
        let Some(current_user) = current_user_sid() else {
            return;
        };
        let regular_file = info(0o100644, 0, 0, VfsFileType::RegularFile);

        let writable = AclMapper::new(false);
        assert_eq!(
            owner_sid(&writable.security_descriptor(&regular_file)),
            current_user,
            "a writable mount must give the mounting account the POSIX owner class"
        );

        let read_only = AclMapper::new(true);
        assert_eq!(
            owner_sid(&read_only.security_descriptor(&regular_file)),
            system_sid()
        );
    }

    #[test]
    fn read_only_mount_strips_write_and_delete_rights() {
        let sd =
            root_mapper(true).security_descriptor(&info(0o040777, 0, 0, VfsFileType::Directory));

        for index in 0..acl_count(&sd) as usize {
            assert_eq!(ace_mask(&sd, index) & FILE_WRITE_RIGHTS, 0);
        }
    }

    #[test]
    fn sticky_directory_does_not_grant_delete_child() {
        let sd =
            root_mapper(false).security_descriptor(&info(0o041777, 0, 0, VfsFileType::Directory));

        for index in 0..acl_count(&sd) as usize {
            assert_eq!(ace_mask(&sd, index) & FILE_DELETE_CHILD, 0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn descriptor_is_valid_for_windows() {
        use windows::Win32::Security::{
            IsValidAcl,
            IsValidSecurityDescriptor,
            IsValidSid,
            PSECURITY_DESCRIPTOR,
            PSID,
        };

        let mode_info = info(0o100644, 0, 0, VfsFileType::RegularFile);
        let mode_sd = root_mapper(false).security_descriptor(&mode_info);
        let (mapper, ..) = mapped_acl_mapper(false);
        let acl_sd = mapper.security_descriptor(&with_acl(
            info(0o100640, 1000, 1000, VfsFileType::RegularFile),
            acl_bytes(&[
                (AclEntryTag::UserObj, 6, u32::MAX),
                (AclEntryTag::User, 7, 1001),
                (AclEntryTag::GroupObj, 7, u32::MAX),
                (AclEntryTag::Group, 5, 1001),
                (AclEntryTag::Mask, 4, u32::MAX),
                (AclEntryTag::Other, 1, u32::MAX),
            ]),
        ));

        for sd in [&mode_sd, &acl_sd] {
            let descriptor = PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut std::ffi::c_void);
            assert!(unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool());

            let acl = dacl_offset(sd);
            assert!(unsafe { IsValidAcl((&sd[acl] as *const u8).cast()) }.as_bool());

            for index in 0..acl_count(sd) as usize {
                let sid = ace_sid(sd, index);
                assert!(
                    unsafe { IsValidSid(PSID(sid.as_ptr() as *mut std::ffi::c_void)) }.as_bool()
                );
            }
        }
    }
}
