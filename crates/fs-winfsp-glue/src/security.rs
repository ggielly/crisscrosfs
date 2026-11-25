//! POSIX → Windows security descriptor mapping.
//!
//! XFS stores Unix `mode`/`uid`/`gid`, while WinFsp expects a self-relative
//! Windows security descriptor.  There is no general uid/gid → Windows account
//! directory on a Windows machine, so this module uses a documented mapping:
//!
//! | XFS identity            | Windows SID                  |
//! |-------------------------|------------------------------|
//! | uid 0 (root)            | `NT AUTHORITY\SYSTEM`        |
//! | gid 0 (root)            | `BUILTIN\Administrators`     |
//! | any other uid           | the mounting process user    |
//! | any other gid           | `NT AUTHORITY\Authenticated Users` |
//! | "other" class           | `Everyone`                   |
//!
//! The mode triad is then translated to three allow ACEs:
//! owner bits → owner SID, group bits → group SID, other bits → Everyone.
//! Read/write/execute map to `FILE_GENERIC_READ`, `FILE_GENERIC_WRITE` and
//! `FILE_GENERIC_EXECUTE`; for directories write also adds `FILE_DELETE_CHILD`.
//!
//! The descriptor is built as a self-relative `SECURITY_DESCRIPTOR_RELATIVE`
//! with a present DACL, so it can be returned directly to WinFsp without any
//! allocation/free dance across the FFI boundary.

use fs_abstraction::types::VfsFileInfo;

const SD_REVISION: u8 = 1;
const SID_REVISION: u8 = 1;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SELF_RELATIVE: u16 = 0x8000;
const ACL_REVISION: u8 = 2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// `FILE_GENERIC_READ`.
const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// `FILE_GENERIC_WRITE`.
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
/// `FILE_GENERIC_EXECUTE`.
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
/// `FILE_DELETE_CHILD`.
const FILE_DELETE_CHILD: u32 = 0x0000_0040;

const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 8;
const SD_HEADER_SIZE: usize = 20;

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

fn authenticated_users_sid() -> Vec<u8> {
    // S-1-5-11
    sid([0, 0, 0, 0, 0, 5], &[11])
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
/// On a normal interactive mount this is the logged-in user; for the service
/// (LocalSystem) it is `S-1-5-18`.  If the token cannot be queried we fall
/// back to `Everyone`, which keeps the volume usable instead of returning an
/// invalid descriptor.
#[cfg(windows)]
fn current_user_sid() -> Vec<u8> {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return everyone_sid();
        }

        let mut length: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut length);
        if length == 0 {
            let _ = CloseHandle(token);
            return everyone_sid();
        }

        let mut buffer = vec![0u8; length as usize];
        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            length,
            &mut length,
        );
        let _ = CloseHandle(token);
        if result.is_err() {
            return everyone_sid();
        }

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let sid_ptr = token_user.User.Sid;
        let sid_len = GetLengthSid(sid_ptr) as usize;
        if sid_len == 0 {
            return everyone_sid();
        }

        std::slice::from_raw_parts(sid_ptr.0 as *const u8, sid_len).to_vec()
    }
}

#[cfg(not(windows))]
fn current_user_sid() -> Vec<u8> {
    everyone_sid()
}

/// Translates a POSIX permission triad into Windows access rights.
fn rights_for(mode_bits: u8, is_directory: bool) -> u32 {
    let mut rights = 0u32;
    if mode_bits & 0b100 != 0 {
        rights |= FILE_GENERIC_READ;
    }
    if mode_bits & 0b010 != 0 {
        rights |= FILE_GENERIC_WRITE;
        if is_directory {
            rights |= FILE_DELETE_CHILD;
        }
    }
    if mode_bits & 0b001 != 0 {
        rights |= FILE_GENERIC_EXECUTE;
    }
    rights
}

/// Builds a self-relative security descriptor with a present DACL.
fn build_security_descriptor(owner: &[u8], group: &[u8], aces: &[(u32, &[u8])]) -> Vec<u8> {
    // ACL header + one ACCESS_ALLOWED_ACE per (mask, SID).
    let acl_len = ACL_HEADER_SIZE
        + aces
            .iter()
            .map(|(_, sid)| ACE_HEADER_SIZE + sid.len())
            .sum::<usize>();
    let mut acl = Vec::with_capacity(acl_len);
    acl.push(ACL_REVISION);
    acl.push(0); // Sbz1
    acl.extend_from_slice(&(acl_len as u16).to_le_bytes());
    acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    acl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2

    for (mask, sid) in aces {
        acl.push(ACCESS_ALLOWED_ACE_TYPE);
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
    sd.extend_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
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
    user_sid: Vec<u8>,
    group_sid: Vec<u8>,
    everyone_sid: Vec<u8>,
    system_sid: Vec<u8>,
    administrators_sid: Vec<u8>,
}

impl AclMapper {
    /// Captures the current process user SID (once per mount).
    pub fn new() -> Self {
        Self {
            user_sid: current_user_sid(),
            group_sid: authenticated_users_sid(),
            everyone_sid: everyone_sid(),
            system_sid: system_sid(),
            administrators_sid: administrators_sid(),
        }
    }

    /// Builds the self-relative security descriptor for `info`.
    pub fn security_descriptor(&self, info: &VfsFileInfo) -> Vec<u8> {
        let mode = info.mode;
        let is_directory = info.is_dir();

        // POSIX owner/group/other triads.
        let owner_bits = ((mode >> 6) & 0b111) as u8;
        let group_bits = ((mode >> 3) & 0b111) as u8;
        let other_bits = (mode & 0b111) as u8;

        let owner_sid: &[u8] = if info.uid == 0 {
            &self.system_sid
        } else {
            &self.user_sid
        };
        let group_sid: &[u8] = if info.gid == 0 {
            &self.administrators_sid
        } else {
            &self.group_sid
        };

        let mut aces: Vec<(u32, &[u8])> = Vec::with_capacity(3);
        let owner_rights = rights_for(owner_bits, is_directory);
        if owner_rights != 0 {
            aces.push((owner_rights, owner_sid));
        }
        let group_rights = rights_for(group_bits, is_directory);
        if group_rights != 0 {
            aces.push((group_rights, group_sid));
        }
        let other_rights = rights_for(other_bits, is_directory);
        if other_rights != 0 {
            aces.push((other_rights, &self.everyone_sid));
        }

        build_security_descriptor(owner_sid, group_sid, &aces)
    }
}

impl Default for AclMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the length of the security descriptor for a WinFsp metadata query.
pub fn security_descriptor_len(info: &VfsFileInfo, mapper: &AclMapper) -> u64 {
    mapper.security_descriptor(info).len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_abstraction::types::{VfsFileType, VfsTimestamp};

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

    fn acl_count(sd: &[u8]) -> u16 {
        let dacl_offset = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
        u16::from_le_bytes(sd[dacl_offset + 4..dacl_offset + 6].try_into().unwrap())
    }

    fn ace_sid(sd: &[u8], index: usize) -> Vec<u8> {
        let dacl_offset = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
        let mut offset = dacl_offset + ACL_HEADER_SIZE;
        for _ in 0..index {
            let size = u16::from_le_bytes(sd[offset + 2..offset + 4].try_into().unwrap()) as usize;
            offset += size;
        }
        let size = u16::from_le_bytes(sd[offset + 2..offset + 4].try_into().unwrap()) as usize;
        sd[offset + ACE_HEADER_SIZE..offset + size].to_vec()
    }

    fn ace_mask(sd: &[u8], index: usize) -> u32 {
        let dacl_offset = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
        let mut offset = dacl_offset + ACL_HEADER_SIZE;
        for _ in 0..index {
            let size = u16::from_le_bytes(sd[offset + 2..offset + 4].try_into().unwrap()) as usize;
            offset += size;
        }
        u32::from_le_bytes(sd[offset + 4..offset + 8].try_into().unwrap())
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

    #[test]
    fn descriptor_is_self_relative_with_dacl() {
        let mapper = AclMapper::new();
        let sd = mapper.security_descriptor(&info(0o100644, 1000, 1000, VfsFileType::RegularFile));

        assert_eq!(sd[0], SD_REVISION);
        let control = u16::from_le_bytes(sd[2..4].try_into().unwrap());
        assert_eq!(control & (SE_SELF_RELATIVE | SE_DACL_PRESENT), 0x8004);
        assert!(u32::from_le_bytes(sd[4..8].try_into().unwrap()) as usize >= SD_HEADER_SIZE);
        assert!(u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize >= SD_HEADER_SIZE);
        assert_eq!(acl_count(&sd), 3);
    }

    #[test]
    fn root_owner_maps_to_system_and_admin_group() {
        let mapper = AclMapper::new();
        let sd = mapper.security_descriptor(&info(0o040755, 0, 0, VfsFileType::Directory));

        assert_eq!(sid_string(&ace_sid(&sd, 0)), "S-1-5-18");
        assert_eq!(sid_string(&ace_sid(&sd, 1)), "S-1-5-32-544");
        assert_eq!(sid_string(&ace_sid(&sd, 2)), "S-1-1-0");
        // Directory write bits include FILE_DELETE_CHILD.
        assert_ne!(ace_mask(&sd, 0) & FILE_DELETE_CHILD, 0);
    }

    #[test]
    fn other_bits_map_to_everyone() {
        let mapper = AclMapper::new();
        let sd = mapper.security_descriptor(&info(0o100004, 1000, 1000, VfsFileType::RegularFile));

        assert_eq!(acl_count(&sd), 1);
        assert_eq!(sid_string(&ace_sid(&sd, 0)), "S-1-1-0");
        assert_eq!(ace_mask(&sd, 0), FILE_GENERIC_READ);
    }

    #[test]
    fn zero_mode_produces_empty_dacl() {
        let mapper = AclMapper::new();
        let sd = mapper.security_descriptor(&info(0o100000, 1000, 1000, VfsFileType::RegularFile));
        assert_eq!(acl_count(&sd), 0);
    }
}
