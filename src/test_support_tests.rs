use crate::test_support::tempdir;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

#[test]
fn private_unique_directories_remove_nested_contents_on_drop() {
    let a = tempdir().unwrap();
    let b = tempdir().unwrap();
    assert_ne!(a.path(), b.path());
    assert_eq!(
        fs::metadata(a.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let path = a.path().to_path_buf();
    fs::create_dir(path.join("nested")).unwrap();
    fs::write(path.join("nested/data"), b"fixture").unwrap();
    drop(a);
    assert!(!path.exists());
    assert!(b.path().exists());
}
#[test]
fn cleanup_does_not_follow_child_symlinks() {
    let outside = tempdir().unwrap();
    let marker = outside.path().join("keep");
    fs::write(&marker, b"fixture").unwrap();
    let inside = tempdir().unwrap();
    symlink(outside.path(), inside.path().join("link")).unwrap();
    let path = inside.path().to_path_buf();
    drop(inside);
    assert!(!path.exists());
    assert_eq!(fs::read(marker).unwrap(), b"fixture");
}
#[test]
fn cleanup_refuses_replaced_root_and_runs_during_unwind() {
    let parent = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let marker = outside.path().join("keep");
    fs::write(&marker, b"fixture").unwrap();
    let victim = tempdir().unwrap();
    let path = victim.path().to_path_buf();
    let saved = parent.path().join("saved");
    fs::rename(&path, &saved).unwrap();
    symlink(outside.path(), &path).unwrap();
    drop(victim);
    assert_eq!(fs::read(marker).unwrap(), b"fixture");
    fs::remove_file(&path).unwrap();
    let victim = tempdir().unwrap();
    let path = victim.path().to_path_buf();
    let result = std::panic::catch_unwind(move || {
        let _guard = victim;
        panic!("synthetic unwind");
    });
    assert!(result.is_err());
    assert!(!path.exists());
}
