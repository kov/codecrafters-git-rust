use core::str;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
#[allow(unused_imports)]
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

type DirName<'a> = &'a str;
type FileName<'a> = &'a str;

fn hash_to_filename(hash: &str) -> (DirName, FileName) {
    (&hash[..2], &hash[2..])
}

fn cat_object(object_id: &str) {
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

    let mut blob = String::new();
    if let Err(e) = ZlibDecoder::new(file).read_to_string(&mut blob) {
        panic!("Failed to decompress object file: {e}");
    }

    let size_end = blob.find('\0').expect("Malformed blob file");
    let contents = &blob.as_str()[size_end + 1..];
    print!("{contents}");
}

fn hash_object(path: &str) {
    let path = PathBuf::from(path);
    let contents = fs::read_to_string(&path).expect("Failed to open file to hash");

    let size = contents.as_bytes().len();
    let blob = format!("blob {size}\0{contents}");

    let mut hasher = Sha1::new();
    hasher.update(blob.as_bytes());

    let hash = hasher.finalize();
    let hash_str = format!("{hash:x}");

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
        .write_all(blob.as_bytes())
        .expect("Failed to write to object file");

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
        _ => println!("unknown command: {}", args[1]),
    }
}
