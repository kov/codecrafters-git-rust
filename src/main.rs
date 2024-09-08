#![feature(concat_bytes)]
use anyhow::{bail, Context, Result};
use cat_file::DisplayMode;
use clap::{ArgGroup, Parser, Subcommand};
use core::str;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use object_store::{ObjectId, ObjectKind};
use sha1::digest::consts::U20;
use sha1::digest::generic_array::GenericArray;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

mod cat_file;
mod object_store;

type DirName<'a> = &'a str;
type FileName<'a> = &'a str;

fn hash_to_filename(hash: &str) -> (DirName, FileName) {
    (&hash[..2], &hash[2..])
}

fn read_object(object_id: &str) -> Vec<u8> {
    let mut object = object_store::read(ObjectId::from_hex(object_id)).unwrap();

    let mut blob = vec![];
    if let Err(e) = object.read_to_end(&mut blob) {
        panic!("Failed to decompress object file: {e}");
    }

    blob
}

fn find_in_slice(haystack: &[u8], start_from: usize, needle: char) -> usize {
    let mut look_ahead = start_from;
    while haystack[look_ahead] as char != needle && look_ahead < haystack.len() {
        look_ahead += 1;
    }
    look_ahead
}

fn ls_tree(object_id: &str) -> Result<()> {
    let blob = read_object(object_id);
    let cursor = blob.as_slice();
    let mut pos = 0;

    while pos < blob.len() {
        // Skip mode.
        pos = find_in_slice(cursor, pos, ' ');
        pos += 1;

        // Name.
        let look_ahead = find_in_slice(cursor, pos, '\0');

        let name = str::from_utf8(&cursor[pos..look_ahead])
            .context("tree contains file with invalid utf-8 name")?;
        println!("{name}");

        // Skip the \0
        pos = look_ahead + 1;

        // Skip the 20-byte hash
        pos += 20;
    }

    Ok(())
}

enum LegacyObjectKind {
    Blob,
    Tree,
    Commit,
}

fn hash_contents(
    contents: &[u8],
    kind: LegacyObjectKind,
) -> (GenericArray<u8, U20>, String, Vec<u8>) {
    let size = contents.len();
    let kind = match kind {
        LegacyObjectKind::Blob => "blob",
        LegacyObjectKind::Tree => "tree",
        LegacyObjectKind::Commit => "commit",
    };

    let mut blob = format!("{kind} {size}\0").into_bytes();
    blob.extend_from_slice(contents);

    let mut hasher = Sha1::new();
    hasher.update(&blob);

    let hash = hasher.finalize();
    (hash, format!("{hash:x}"), blob)
}

fn write_hash_object(contents: &[u8], kind: LegacyObjectKind) -> (GenericArray<u8, U20>, String) {
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

fn hash_object(path: &Path) -> Result<()> {
    let contents = fs::read_to_string(&path).with_context(|| "reading from '{path}' to hash")?;

    let (_, hash_str) = write_hash_object(contents.as_bytes(), LegacyObjectKind::Blob);
    println!("{hash_str}");
    Ok(())
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
            let (hash, _, _) = hash_contents(&file_contents, LegacyObjectKind::Blob);
            hash
        };
        contents.extend(name.as_bytes());
        contents.push(b'\0');
        contents.extend(hash);
    }

    write_hash_object(&contents, LegacyObjectKind::Tree)
}

fn write_tree() -> Result<()> {
    let (_, hash_str) = do_write_tree(&PathBuf::from("."));
    println!("{hash_str}");
    Ok(())
}

fn commit_tree(tree_hash: &str, parent_hash: &str, message: &str) -> Result<()> {
    let mut contents = format!("tree {tree_hash}\nparent {parent_hash}\n");
    contents.push_str("author Gustavo Noronha Silva <gustavo@noronha.dev.br> 1725324599 -0300\n");
    contents
        .push_str("committer Gustavo Noronha Silva <gustavo@noronha.dev.br> 1725324599 -0300\n");
    contents.push('\n');
    contents.push_str(message);
    contents.push('\n');

    let (_, hash_str) = write_hash_object(contents.as_bytes(), LegacyObjectKind::Commit);
    println!("{hash_str}");
    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init,

    #[command(
        group = ArgGroup::new("display_mode")
        .args(&["pretty_print", "type_only", "size_only"])
    )]
    CatFile {
        #[clap(short = 'p')]
        pretty_print: bool,

        #[clap(short = 't')]
        type_only: bool,

        #[clap(short = 's')]
        size_only: bool,

        // kind must be provided if none of the short options above are
        first: Option<String>,
        second: Option<String>,
    },

    HashObject {
        #[clap(short = 'w')]
        write: bool,

        path: PathBuf,
    },

    LsTree {
        #[clap(long = "name-only")]
        name_only: bool,

        hash: String,
    },

    WriteTree,

    CommitTree {
        #[clap(short = 'p')]
        parent: String,

        #[clap(short = 'm')]
        message: String,

        hash: String,
    },
}

fn main() -> Result<()> {
    // Uncomment this block to pass the first stage
    let args = Args::parse();
    match args.command {
        Command::Init => object_store::init(),
        Command::CatFile {
            pretty_print,
            type_only,
            size_only,
            first,
            second,
        } => {
            let (expected_kind, hex) = if pretty_print || type_only || size_only {
                let (Some(hex), None) = (first, second) else {
                    bail!("hash must be provided when one of -p, -s or -t are")
                };
                (None, hex)
            } else {
                let (Some(kind), Some(hex)) = (first, second) else {
                    bail!("kind and hex must be provided when none of -p, -s or -t are")
                };
                (Some(kind), hex)
            };

            let display_mode = if pretty_print {
                DisplayMode::PrettyPrint
            } else if type_only {
                DisplayMode::Type
            } else if size_only {
                DisplayMode::Size
            } else {
                DisplayMode::Raw
            };

            cat_file::run(
                ObjectId::from_hex(hex),
                expected_kind.map(|kind| match kind.as_str() {
                    "blob" => ObjectKind::Blob,
                    "tree" => ObjectKind::Tree,
                    "commit" => ObjectKind::Commit,
                    unknown => panic!("unknown blob type {unknown}"),
                }),
                display_mode,
            )
        }
        Command::HashObject { write: _, path } => hash_object(&path),
        Command::LsTree { name_only: _, hash } => ls_tree(&hash),
        Command::WriteTree => write_tree(),
        Command::CommitTree {
            parent,
            message,
            hash,
        } => commit_tree(&hash, &parent, &message),
    }
}
