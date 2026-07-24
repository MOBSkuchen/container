//! Archive extraction hardened for untrusted input.
//!
//! The `tar` and `zip` crates already refuse plain `..` traversal; the checks
//! here close the classic remaining gap — a link entry whose target points
//! outside the destination, through which a later entry (or the instance
//! itself) could escape the unpack dir.

use std::io::{Error, ErrorKind, Read, Result, Seek};
use std::path::{Component, Path};

/// Lexical check: does `path` climb out of the directory it is relative to?
/// No filesystem access, so it also covers targets that do not exist yet.
fn escapes(path: &Path) -> bool {
    let mut depth = 0i32;
    for component in path.components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            // Absolute targets point wherever they like.
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

pub fn untar<R: Read>(mut tar: tar::Archive<R>, dest: &Path) -> Result<()> {
    // `unpack_in` canonicalizes `dest`, so unlike `unpack` it must exist.
    std::fs::create_dir_all(dest)?;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if let Some(target) = entry.link_name()? {
            // The target resolves relative to the entry's own directory.
            let anchor = entry.path()?.parent().map(Path::to_path_buf).unwrap_or_default();
            if escapes(&anchor.join(&target)) {
                return Err(Error::new(ErrorKind::InvalidData, format!(
                    "link '{}' -> '{}' points outside the archive",
                    entry.path()?.display(), target.display(),
                )));
            }
        }
        // `unpack_in` reports (rather than unpacks) entries that would land
        // outside `dest`.
        if !entry.unpack_in(dest)? {
            return Err(Error::new(ErrorKind::InvalidData, format!(
                "entry '{}' escapes the destination", entry.path()?.display(),
            )));
        }
    }
    Ok(())
}

pub fn unzip<R: Read + Seek>(mut zip: zip::ZipArchive<R>, dest: &Path) -> Result<()> {
    // `extract` sanitizes names itself; rejecting up front turns a partial
    // unpack into a clean refusal.
    for i in 0..zip.len() {
        let entry = zip.by_index_raw(i).map_err(Error::other)?;
        if entry.enclosed_name().is_none() {
            return Err(Error::new(ErrorKind::InvalidData, format!(
                "zip entry '{}' escapes the destination", entry.name(),
            )));
        }
    }
    zip.extract(dest).map_err(Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tarball(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> tar::Archive<std::io::Cursor<Vec<u8>>> {
        let mut builder = tar::Builder::new(Vec::new());
        build(&mut builder);
        tar::Archive::new(std::io::Cursor::new(builder.into_inner().unwrap()))
    }

    fn symlink_entry(builder: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        builder.append_link(&mut header, path, target).unwrap();
    }

    fn file_entry(builder: &mut tar::Builder<Vec<u8>>, path: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        builder.append_data(&mut header, path, &b"hi"[..]).unwrap();
    }

    // `escapes` is checked directly for the allowed cases: actually creating
    // symlinks needs elevation on Windows, which a test must not depend on.
    #[test]
    fn link_targets_inside_the_archive_are_allowed() {
        for target in ["a.txt", "sub/a.txt", "sub/../a.txt", "./a.txt"] {
            assert!(!escapes(Path::new(target)), "'{target}' was refused");
        }
    }

    #[test]
    fn plain_files_unpack() {
        let dest = std::env::temp_dir().join(format!("chld-untar-ok-{:08x}", rand::random::<u32>()));
        untar(tarball(|b| file_entry(b, "sub/a.txt")), &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("sub").join("a.txt")).unwrap(), b"hi");
        let _ = std::fs::remove_dir_all(&dest);
    }

    // Refusal happens before anything touches the filesystem, so these run
    // without symlink rights.
    #[test]
    fn escaping_link_targets_are_refused() {
        let dest = std::env::temp_dir().join(format!("chld-untar-esc-{:08x}", rand::random::<u32>()));
        for target in ["../outside", "sub/../../outside", "/etc/passwd", "C:\\Windows\\win.ini"] {
            let archive = tarball(|b| symlink_entry(b, "link", target));
            assert!(untar(archive, &dest).is_err(), "'{target}' was accepted");
        }
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0, "a refused archive still created files");
        let _ = std::fs::remove_dir_all(&dest);
    }
}
