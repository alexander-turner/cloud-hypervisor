// Copyright © 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::io::Error as IoError;
use std::path::Path;
#[cfg(test)]
use std::ptr;

#[cfg(test)]
use landlock::make_bitflags;
use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, path_beneath_rules,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LandlockError {
    /// All RulesetErrors from Landlock library are wrapped in this error
    #[error("Error creating/adding/restricting ruleset")]
    ManageRuleset(#[source] RulesetError),

    /// Error opening path
    #[error("Error opening path")]
    OpenPath(#[source] IoError),

    /// Invalid Landlock access
    #[error("Invalid Landlock access: {0}")]
    InvalidLandlockAccess(String),

    /// Invalid Path
    #[error("Invalid path")]
    InvalidPath,
}

// https://docs.rs/landlock/latest/landlock/enum.ABI.html for more info on ABI
// A kernel without the rights of ABI_FLOOR makes Landlock::new() fail.
static ABI_FLOOR: ABI = ABI::V3;
// Rights newer than ABI_FLOOR, up to ABI, are used only where the kernel has them.
static ABI: ABI = ABI::V9;

#[derive(Debug)]
pub(crate) struct LandlockAccess {
    access: BitFlags<AccessFs>,
}

impl TryFrom<&str> for LandlockAccess {
    type Error = LandlockError;

    fn try_from(s: &str) -> Result<LandlockAccess, LandlockError> {
        if s.is_empty() {
            return Err(LandlockError::InvalidLandlockAccess(
                "Access cannot be empty".to_string(),
            ));
        }

        let mut access = BitFlags::<AccessFs>::empty();
        for c in s.chars() {
            match c {
                // IoctlDev is also granted with 'r': CH queries the size of a
                // read-only block device with BLKGETSIZE64, and the kernel
                // refuses BLKDISCARD and BLKZEROOUT on a read-only fd.
                'r' => access |= AccessFs::from_read(ABI) | AccessFs::IoctlDev,
                // From ABI V5 this includes IoctlDev, and from ABI V9 it
                // includes ResolveUnix (connect to a pathname UNIX socket).
                'w' => access |= AccessFs::from_write(ABI),
                _ => {
                    return Err(LandlockError::InvalidLandlockAccess(
                        format!("Invalid access: {c}").to_string(),
                    ));
                }
            }
        }
        Ok(LandlockAccess { access })
    }
}
pub struct Landlock {
    ruleset: RulesetCreated,
}

impl Landlock {
    pub fn new() -> Result<Landlock, LandlockError> {
        // The ABI_FLOOR rights are a hard requirement. The newer rights are
        // best effort: the kernel handles the ones it supports, and rules
        // drop the ones it does not, so an older kernel behaves as before.
        let def_ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI_FLOOR))
            .map_err(LandlockError::ManageRuleset)?
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(ABI))
            .map_err(LandlockError::ManageRuleset)?;

        let ruleset = def_ruleset.create().map_err(LandlockError::ManageRuleset)?;

        Ok(Landlock { ruleset })
    }

    fn add_rule(&mut self, path: &Path, access: BitFlags<AccessFs>) -> Result<(), LandlockError> {
        // path_beneath_rules in landlock crate handles file and directory access rules.
        // Incoming path/s are passed to path_beneath_rules, so that we don't
        // have to worry about the type of the path.
        let paths = vec![&path];
        let path_beneath_rules = path_beneath_rules(paths, access);
        self.ruleset
            .as_mut()
            .add_rules(path_beneath_rules)
            .map_err(LandlockError::ManageRuleset)?;
        Ok(())
    }

    pub(crate) fn add_rule_with_access(
        &mut self,
        path: &Path,
        access: &str,
    ) -> Result<(), LandlockError> {
        self.add_rule(path, LandlockAccess::try_from(access)?.access)?;
        Ok(())
    }

    pub fn restrict_self(self) -> Result<(), LandlockError> {
        self.ruleset
            .restrict_self()
            .map_err(LandlockError::ManageRuleset)?;
        Ok(())
    }
}

#[test]
fn test_try_from_access() {
    // These access rights could change in future versions of Landlock. Listing
    // them here explicitly to raise their visibility during code reviews.
    let read_access = make_bitflags!(AccessFs::{
        Execute
        | ReadFile
        | ReadDir
        | IoctlDev
    });
    let write_access = make_bitflags!(AccessFs::{
        WriteFile
        | RemoveDir
        | RemoveFile
        | MakeChar
        | MakeDir
        | MakeReg
        | MakeSock
        | MakeFifo
        | MakeBlock
        | MakeSym
        | Refer
        | Truncate
        | IoctlDev
        | ResolveUnix
    });
    let landlock_access = LandlockAccess::try_from("rw").unwrap();
    assert_eq!(landlock_access.access, read_access | write_access);

    let landlock_access = LandlockAccess::try_from("r").unwrap();
    assert_eq!(landlock_access.access, read_access);

    let landlock_access = LandlockAccess::try_from("w").unwrap();
    assert_eq!(landlock_access.access, write_access);

    LandlockAccess::try_from("").unwrap_err();
}

#[test]
fn test_new_requires_abi_floor() {
    // SAFETY: a NULL attr with LANDLOCK_CREATE_RULESET_VERSION only returns the
    // kernel's Landlock ABI version, or -1.
    let kernel_abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    let landlock = Landlock::new();
    assert_eq!(landlock.is_ok(), kernel_abi >= 3, "kernel ABI {kernel_abi}");

    // Rights newer than the kernel's ABI must not make a rule fail.
    if let Ok(mut landlock) = landlock {
        landlock.add_rule_with_access(Path::new("/"), "rw").unwrap();
    }
}
