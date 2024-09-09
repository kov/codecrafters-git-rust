use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fs;
use std::io::{self, Read, Write};

use crate::hash_object;
use crate::object_store::{path_from_git_root, read, test::*, ObjectId, ObjectKind};

fn write_2b_tree() {
    let blob = include_bytes!("test-files/2b/297e643c551e76cfa1f93810c50811382f9117");
    write_blob_file("2b", "297e643c551e76cfa1f93810c50811382f9117", &blob[..]);
}

#[test]
fn test_objectid() {
    let bytes = [
        43, 41, 126, 100, 60, 85, 30, 118, 207, 161, 249, 56, 16, 197, 8, 17, 56, 47, 145, 23,
    ];
    let hex = "2b297e643c551e76cfa1f93810c50811382f9117";

    let oid = ObjectId::from_bytes(bytes.clone());
    assert_eq!(oid.hex, hex);

    let oid = ObjectId::from_hex(hex.to_string());
    assert_eq!(oid.hash, bytes);
}

#[test]
fn test_read_tree() {
    let _tmp_dir = init_repo();

    write_2b_tree();

    let mut oread = read(ObjectId::from_hex(
        "2b297e643c551e76cfa1f93810c50811382f9117",
    ))
    .expect("Unable to read test object tree");

    assert_eq!(oread.oid.hex, "2b297e643c551e76cfa1f93810c50811382f9117");
    assert!(matches!(oread.kind, ObjectKind::Tree));

    let mut buf = vec![];
    oread
        .read_to_end(&mut buf)
        .expect("Reading contents of the tree blob file");

    assert_eq!(
        &buf,
        &concat_bytes!(
            b"100644 test.txt\0",
            [
                157, 174, 175, 185, 134, 76, 244, 48, 85, 174, 147, 190, 176, 175, 214, 199, 209,
                68, 191, 164,
            ]
        )
    );
}

#[test]
fn test_read_tree_larger() {
    let _tmp_dir = init_repo();

    // Write a tree object whose content goes beyond the expected size declared
    // on the header.
    let mut contents = ZlibEncoder::new(vec![], Compression::default());
    contents.write_all(b"tree 36\0").expect("Writing test data");
    contents
        .write_all(str::repeat("-", 40).as_bytes())
        .expect("Writing test data");
    let contents = contents.finish().expect("Failed to compress test data");

    write_blob_file("2b", "297e643c551e76cfa1f93810c50811382f9117", &contents);

    let mut oread = read(ObjectId::from_hex(
        "2b297e643c551e76cfa1f93810c50811382f9117",
    ))
    .expect("Unable to read test object tree");

    let mut buf = vec![];
    let Err(err) = oread.read_to_end(&mut buf) else {
        panic!("Expected read to fail, but it succeeded.");
    };

    assert!(matches!(err.kind(), io::ErrorKind::Other));
}

#[test]
fn test_hash_object() {
    let tmp_dir = init_repo();

    let path = tmp_dir.path().join("test.txt");
    let mut test_txt = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&path)
        .expect("Failed to create test file");

    write!(test_txt, "test\ntest\n").expect("Failed to write to test file");

    for should_write in [false, true] {
        let oid = hash_object::run(&path, should_write).expect("Failed to hash object");
        assert_eq!(oid.hex, "dec2cbe1fa34fe8d08aa4031b70da63b6399cc3f");

        assert_eq!(
            fs::exists(
                path_from_git_root(".git/objects/de/c2cbe1fa34fe8d08aa4031b70da63b6399cc3f")
                    .expect("Failed to get path for assert")
            )
            .expect("Failed to assert file existance"),
            should_write
        );
    }
}
