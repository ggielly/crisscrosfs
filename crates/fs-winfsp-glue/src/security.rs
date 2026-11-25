//! POSIX → Windows security descriptor mapping.
//!
//! XFS stores Unix `mode`/`uid`/`gid`, while WinFsp expects a self-relative
//! Windows security descriptor.  There is no general uid/gid → Windows account
//! directory on Windows, so identities are mapped explicitly:
//!
//! * uid 0 → `NT AUTHORITY\SYSTEM`
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
//! Read-only mounts never grant write or delete rights.  Sticky directories do
//! not receive `FILE_DELETE_CHILD`; setuid/setgid have no Windows ACL
//! equivalent and are intentionally ignored.

use std::collections::BTreeMap;

use fs_abstraction::types::VfsFileInfo;
use serde::Deserialize;

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

/// Builds security descriptors for XFS inode metadata.
pub struct AclMapper {
    read_only: bool,
    uid_map: BTreeMap<u32, Vec<u8>>,
    gid_map: BTreeMap<u32, Vec<u8>>,
    everyone_sid: Vec<u8>,
    system_sid: Vec<u8>,
    administrators_sid: Vec<u8>,
}

impl AclMapper {
    /// Creates a mapper from `XFS_ACL_MAP` (if set).
    ///
    /// Root is always mapped.  Non-root ids are only granted access through
    /// explicit mappings; token lookup failure therefore cannot broaden access.
    pub fn new(read_only: bool) -> Self {
        let mut uid_map = BTreeMap::from([(0, system_sid())]);
        let mut gid_map = BTreeMap::from([(0, administrators_sid())]);
        let current_user = current_user_sid();

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
        uid_map.entry(0).or_insert_with(system_sid);
        gid_map.entry(0).or_insert_with(administrators_sid);

        Self {
            read_only,
            uid_map,
            gid_map,
            everyone_sid: everyone_sid(),
            system_sid: system_sid(),
            administrators_sid: administrators_sid(),
        }
    }

    /// Builds the self-relative security descriptor for `info`.
    pub fn security_descriptor(&self, info: &VfsFileInfo) -> Vec<u8> {
        let Some(owner_sid) = self.uid_map.get(&info.uid) else {
            // Without an owner mapping we cannot know which caller must use
            // the owner class instead of group/other.  Fail closed.
            return build_security_descriptor(&self.system_sid, &self.administrators_sid, &[]);
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
        if owner_rights != 0 {
            aces.push((ACCESS_ALLOWED_ACE_TYPE, owner_rights, owner_sid));
        }
        if group_rights != 0 {
            aces.push((ACCESS_ALLOWED_ACE_TYPE, group_rights, group_sid.unwrap()));
        }
        if other_rights != 0 {
            aces.push((ACCESS_ALLOWED_ACE_TYPE, other_rights, &self.everyone_sid));
        }

        // POSIX owner class wins over group/other.  A matching deny ACE removes
        // any overlapping rights that Windows would otherwise union.
        let owner_deny = (group_rights | other_rights) & !owner_rights;
        if owner_deny != 0 {
            aces.push((ACCESS_DENIED_ACE_TYPE, owner_deny, owner_sid));
        }

        // POSIX group class wins over other.  If owner and group map to the
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

        build_security_descriptor(
            owner_sid,
            group_sid.unwrap_or(&self.administrators_sid),
            &aces,
        )
    }
}

#[cfg(test)]
mod tests {
    use fs_abstraction::types::{VfsFileType, VfsTimestamp};

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
    fn other_bits_map_to_everyone() {
        let sd =
            root_mapper(false).security_descriptor(&info(0o100004, 0, 0, VfsFileType::RegularFile));

        assert_eq!(acl_count(&sd), 3);
        assert_eq!(ace_type(&sd, 0), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 0)), "S-1-1-0");
        assert_eq!(ace_mask(&sd, 0), FILE_GENERIC_READ);
        // Owner and group must not inherit the "other" class.
        assert_eq!(ace_type(&sd, 1), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 1)), "S-1-5-18");
        assert_eq!(ace_type(&sd, 2), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 2)), "S-1-5-32-544");
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
        assert_eq!(ace_type(&sd, 0), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 0), owner);
        assert_eq!(ace_type(&sd, 1), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 1)), "S-1-1-0");
        assert_eq!(ace_type(&sd, 2), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 2), owner);
        assert_eq!(ace_mask(&sd, 2), FILE_GENERIC_READ & !FILE_GENERIC_WRITE);
        assert_eq!(ace_type(&sd, 3), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 3), group);
        assert_eq!(ace_mask(&sd, 3), FILE_GENERIC_READ);
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
        assert_eq!(ace_type(&sd, 0), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 0), group);
        assert_eq!(ace_type(&sd, 1), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(sid_string(&ace_sid(&sd, 1)), "S-1-1-0");
        assert_eq!(ace_type(&sd, 2), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 2), owner);
        assert_eq!(
            ace_mask(&sd, 2) & FILE_GENERIC_EXECUTE,
            FILE_GENERIC_EXECUTE
        );
        assert_eq!(ace_type(&sd, 3), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(ace_sid(&sd, 3), group);
        assert_eq!(ace_mask(&sd, 3), FILE_GENERIC_EXECUTE & !FILE_GENERIC_READ);
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

        let sd =
            root_mapper(false).security_descriptor(&info(0o100644, 0, 0, VfsFileType::RegularFile));
        let descriptor = PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut std::ffi::c_void);
        assert!(unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool());

        let acl = dacl_offset(&sd);
        assert!(unsafe { IsValidAcl((&sd[acl] as *const u8).cast()) }.as_bool());

        for index in 0..acl_count(&sd) as usize {
            let sid = ace_sid(&sd, index);
            assert!(unsafe { IsValidSid(PSID(sid.as_ptr() as *mut std::ffi::c_void)) }.as_bool());
        }
    }
}
