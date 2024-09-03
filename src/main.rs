use core::str;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::digest::consts::U20;
use sha1::digest::generic_array::GenericArray;
use sha1::{Digest, Sha1};
#[allow(unused_imports)]
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

type DirName<'a> = &'a str;
type FileName<'a> = &'a str;

fn hash_to_filename(hash: &str) -> (DirName, FileName) {
    (&hash[..2], &hash[2..])
}

fn read_object(object_id: &str) -> Vec<u8> {
    let (dir_name, file_name) = hash_to_filename(object_id);

    let mut path = PathBuf::from(".git/objects");
    path.push(dir_name);

    let Ok(_) = fs::exists(&path) else {
        panic!("Object directory {dir_name} does not exist showing object {object_id}");
    };

    path.push(file_name);
    let Ok(file) = fs::File::open(&path) else {
        panic!("Unable to open object file with id {object_id}");
    };

    let mut blob = vec![];
    if let Err(e) = ZlibDecoder::new(file).read_to_end(&mut blob) {
        panic!("Failed to decompress object file: {e}");
    }

    blob
}

fn cat_object(object_id: &str) {
    let blob =
        String::from_utf8(read_object(object_id)).expect("file contents are not valid UTF-8");
    let size_end = blob.find('\0').expect("Malformed blob file");
    let contents = &blob.as_str()[size_end + 1..];
    print!("{contents}");
}

fn find_in_slice(haystack: &[u8], start_from: usize, needle: char) -> usize {
    let mut look_ahead = start_from;
    while haystack[look_ahead] as char != needle && look_ahead < haystack.len() {
        look_ahead += 1;
    }
    look_ahead
}

fn ls_tree(object_id: &str) {
    let blob = read_object(object_id);
    let cursor = blob.as_slice();
    let mut pos = 5;

    // Skip header.
    assert_eq!(str::from_utf8(&cursor[..pos]), Ok("tree "));

    // Obtain length.
    let look_ahead = find_in_slice(cursor, pos, '\0');

    let size = str::from_utf8(&cursor[pos..look_ahead])
        .expect("Expected file size, found non-utf8 value")
        .parse::<usize>()
        .expect("Invalid number reading tree object file size");

    pos = look_ahead + 1; // Skip the \0.

    assert_eq!(size, cursor.len() - pos);

    while pos <= size {
        // Skip mode.
        pos = find_in_slice(cursor, pos, ' ');
        pos += 1;

        // Name.
        let look_ahead = find_in_slice(cursor, pos, '\0');

        let name = str::from_utf8(&cursor[pos..look_ahead])
            .expect("Tree contains file with invalid utf-8 name");
        println!("{name}");

        // Skip the \0
        pos = look_ahead + 1;

        // Skip the 20-byte hash
        pos += 20;
    }
}

enum ObjectKind {
    Blob,
    Tree,
    Commit,
}

fn hash_contents(contents: &[u8], kind: ObjectKind) -> (GenericArray<u8, U20>, String, Vec<u8>) {
    let size = contents.len();
    let kind = match kind {
        ObjectKind::Blob => "blob",
        ObjectKind::Tree => "tree",
        ObjectKind::Commit => "commit",
    };

    let mut blob = format!("{kind} {size}\0").into_bytes();
    blob.extend_from_slice(contents);

    let mut hasher = Sha1::new();
    hasher.update(&blob);

    let hash = hasher.finalize();
    (hash, format!("{hash:x}"), blob)
}

fn write_hash_object(contents: &[u8], kind: ObjectKind) -> (GenericArray<u8, U20>, String) {
    let (hash, hash_str, blob) = hash_contents(contents, kind);

    let mut object_path = PathBuf::from(".git/objects");

    let (dir_name, file_name) = hash_to_filename(&hash_str);
    object_path.push(dir_name);

    fs::create_dir(&object_path).expect("Unable to create object directory");

    object_path.push(file_name);

    let mut object_file = ZlibEncoder::new(
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&object_path)
            .expect("Failed to create object file"),
        Compression::best(),
    );

    object_file
        .write_all(&blob)
        .expect("Failed to write to object file");

    (hash, hash_str)
}

fn hash_object(path: &str) {
    let path = PathBuf::from(path);
    let contents = fs::read_to_string(&path).expect("Failed to open file to hash");

    let (_, hash_str) = write_hash_object(contents.as_bytes(), ObjectKind::Blob);
    println!("{hash_str}");
}

fn do_write_tree(dir_path: &Path) -> (GenericArray<u8, U20>, String) {
    let mut entries = vec![];

    fs::read_dir(dir_path)
        .expect("Failed to read current directory")
        .for_each(|entry| {
            let entry = entry.expect("Failed to read directory entry");
            entries.push(entry.path());
        });

    // Tree objects expect alphabetical sorted entries.
    entries.sort();

    let mut contents: Vec<u8> = vec![];
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy();

        if name == ".git" {
            continue;
        }

        let hash = if path.is_dir() {
            contents.extend(b"40000 ");

            let (hash, _) = do_write_tree(&path);
            hash
        } else {
            contents.extend(b"100644 ");

            let mut file_contents = vec![];
            fs::File::open(&path)
                .expect("Failed to open file to hash")
                .read_to_end(&mut file_contents)
                .expect("Failed to read file to hash");
            let (hash, _, _) = hash_contents(&file_contents, ObjectKind::Blob);
            hash
        };
        contents.extend(name.as_bytes());
        contents.push(b'\0');
        contents.extend(hash);
    }

    write_hash_object(&contents, ObjectKind::Tree)
}

fn write_tree() {
    let (_, hash_str) = do_write_tree(&PathBuf::from("."));
    println!("{hash_str}");
}

fn commit_tree(tree_hash: &str, parent_hash: &str, message: &str) {
    let mut contents = format!("tree {tree_hash}\nparent {parent_hash}\n");
    contents.push_str("author Gustavo Noronha Silva <gustavo@noronha.dev.br> 1725324599 -0300\n");
    contents
        .push_str("committer Gustavo Noronha Silva <gustavo@noronha.dev.br> 1725324599 -0300\n");
    contents.push('\n');
    contents.push_str(message);
    contents.push('\n');

    let (_, hash_str) = write_hash_object(contents.as_bytes(), ObjectKind::Commit);
    println!("{hash_str}");
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    // println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let args: Vec<String> = env::args().collect();
    match args[1].as_str() {
        "init" => {
            fs::create_dir(".git").unwrap();
            fs::create_dir(".git/objects").unwrap();
            fs::create_dir(".git/refs").unwrap();
            fs::write(".git/HEAD", "ref: refs/heads/master\n").unwrap();
            println!("Initialized git directory");
        }
        "cat-file" => {
            assert_eq!(args[2].as_str(), "-p");
            cat_object(args[3].as_str());
        }
        "hash-object" => {
            assert_eq!(args[2].as_str(), "-w");
            hash_object(args[3].as_str());
        }
        "ls-tree" => {
            assert_eq!(args[2].as_str(), "--name-only");
            ls_tree(args[3].as_str());
        }
        "write-tree" => {
            write_tree();
        }
        "commit-tree" => {
            assert_eq!(args[3].as_str(), "-p");
            assert_eq!(args[5].as_str(), "-m");
            commit_tree(args[2].as_str(), args[4].as_str(), args[6].as_str());
        }
        _ => println!("unknown command: {}", args[1]),
    }
}
