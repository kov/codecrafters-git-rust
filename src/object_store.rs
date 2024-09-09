use anyhow::{anyhow, bail, Context, Result};
use core::str;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::fmt::Display;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::{cmp, env, fs};
use temp_file::{TempFile, TempFileBuilder};

#[cfg(not(test))]
use std::os::unix::fs::MetadataExt;

#[cfg(test)]
use std::cell::RefCell;

// This is so we can override path resolution for testing, so that we are able to run
// more than one test in a row, as we do not need to rely on current working directory.
#[cfg(test)]
thread_local!(static TMPDIR: RefCell<PathBuf> = RefCell::new(PathBuf::from("/unset")));

#[cfg(test)]
pub fn path_from_git_root(subpath: impl AsRef<Path>) -> Result<PathBuf> {
    let mut full_path = Default::default();
    TMPDIR.with_borrow(|path| {
        if path == &PathBuf::from("/unset") {
            panic!("TMPDIR used before being set");
        }

        full_path = path.join(subpath.as_ref());
    });

    Ok(full_path)
}

#[cfg(not(test))]
fn path_from_git_root(subpath: impl AsRef<Path>) -> Result<PathBuf> {
    let mut candidate = env::current_dir()?;
    let starting_device = candidate.metadata()?.dev();

    let path = loop {
        let path = candidate.join(".git");
        if path.try_exists()? {
            break Some(path);
        }

        if candidate.parent().is_none() {
            break None;
        }

        candidate = candidate.parent().unwrap().to_owned();
        if candidate.metadata()?.dev() != starting_device {
            break None;
        }
    };

    // We either found an existing .git we should use as our anchor, or
    // we haven't, in which case we assume current directory.
    match path {
        Some(_) => Ok(candidate.join(subpath)),
        None => Ok(env::current_dir()?.join(subpath.as_ref())),
    }
}

// A wrapper for fs::create_dir() that automatically ignores errors for
// the directory already existing. When running tests it will use
// path_from_git_root() to allow overriding of working directory.
#[inline]
fn ensure_dir(path: &str) -> Result<()> {
    // For tests we want to be able to override the path, but normally
    // we must just use the current working directory.
    #[cfg(test)]
    let path = path_from_git_root(&path)?;

    fs::create_dir(path).or_else(|e| {
        if matches!(e.kind(), io::ErrorKind::AlreadyExists) {
            Ok(())
        } else {
            Err(anyhow!(e))
        }
    })
}

#[inline]
fn object_storage_path() -> Result<PathBuf> {
    path_from_git_root(".git/objects")
}

pub fn init() -> Result<()> {
    let is_reinit = fs::exists(".git")?;

    ensure_dir(".git")?;
    ensure_dir(".git/objects")?;
    ensure_dir(".git/refs")?;

    if is_reinit {
        println!(
            "Reinitialized existing Git repository in {}",
            env::current_dir()?.display()
        )
    } else {
        fs::write(".git/HEAD", "ref: refs/heads/main\n")?;
        println!(
            "Initialized empty Git repository in {}",
            env::current_dir()?.display()
        );
    }
    Ok(())
}

#[allow(unused)]
pub struct ObjectId {
    pub hash: [u8; 20],
    pub hex: String,
}

#[allow(unused)]
impl ObjectId {
    pub fn from_bytes(hash: [u8; 20]) -> Self {
        let hex = hex::encode(&hash);
        ObjectId { hash, hex }
    }

    pub fn from_hex(hex: impl Into<String>) -> Self {
        let hex = hex.into();
        let throw = |e| panic!("Failed to decode hex for {hex}: {e}");
        let hash: [u8; 20] = hex::decode(&hex).unwrap_or_else(throw).try_into().unwrap();
        ObjectId { hash, hex }
    }
}

// git stores objects with the 2 first characters of the hex as a directory
// and the rest as the name of the file.
#[inline]
fn hash_to_filename(hash: &str) -> (&str, &str) {
    (&hash[..2], &hash[2..])
}

#[derive(Clone, PartialEq, Debug)]
pub enum ObjectKind {
    Blob,
    Tree,
    Commit,
}

impl Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ObjectKind::Blob => "blob",
            ObjectKind::Tree => "tree",
            ObjectKind::Commit => "commit",
        };
        write!(f, "{s}")
    }
}

#[allow(unused)]
pub struct ObjectRead<R> {
    pub oid: ObjectId,
    pub kind: ObjectKind,
    pub size: usize,

    read: usize,
    reader: R,
}

// Opens the object with the given hash for reading, wrapping it on a zlib decoders
// and processing the header. The header format is:
//
// {type}<whitespace>{size}\0
//
// The caller can use the returned ObjectRead struct to do the actual reading of the bytes.
pub fn read(oid: ObjectId) -> Result<ObjectRead<impl BufRead>> {
    let (dir_name, file_name) = hash_to_filename(&oid.hex);

    let mut path = object_storage_path()?;
    path.push(dir_name);

    fs::exists(&path).with_context(|| {
        format!(
            "Reading directory {dir_name} while reading object {}",
            oid.hex
        )
    })?;

    path.push(file_name);
    let Ok(file) = fs::File::open(&path) else {
        panic!("Unable to open object file with id {}", oid.hex);
    };

    let mut reader = BufReader::new(ZlibDecoder::new(file));

    let mut buf = vec![];
    reader
        .read_until(b' ', &mut buf)
        .with_context(|| format!("reading header for object {}", oid.hex))?;

    let kind = match str::from_utf8(&buf).map(|s| s.trim_end()) {
        Ok("blob") => ObjectKind::Blob,
        Ok("tree") => ObjectKind::Tree,
        Ok("commit") => ObjectKind::Commit,
        Ok(name) => bail!("Unknown object type '{name}'"),
        Err(e) => bail!("Object type name was not valid UTF-8: {e}"),
    };

    buf.clear();
    reader
        .read_until(b'\0', &mut buf)
        .with_context(|| format!("reading size for object {} from header", oid.hex))?;

    let size = str::from_utf8(&mut buf)
        .map(|s| s.trim_end_matches('\0'))
        .with_context(|| format!("size in header for object {} was not ascii", oid.hex))?
        .parse()
        .with_context(|| format!("Parsing size from object {} header", oid.hex))?;

    Ok(ObjectRead {
        oid,
        kind,
        size,
        read: 0,
        reader,
    })
}

impl<R: BufRead> Read for ObjectRead<R> {
    // This custom read implementation will read up to the number of bytes
    // the object header told us to expect and will produce an error if
    // there are more or fewer bytes than expected.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left_to_read = self.size - self.read;

        if left_to_read == 0 {
            // At this point we read everything we expected to read. If we read
            // anything else the file probably changed from under us, so it should
            // be treated as an error.
            self.reader.read(buf).and_then(|n| {
                if n != 0 {
                    self.read += n;
                    // TODO: replace with FileTooLarge once it is stabilized.
                    // https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.FileTooLarge
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        "File is larger than expected",
                    ))
                } else {
                    Ok(n)
                }
            })
        } else {
            let bytes_to_read = cmp::min(left_to_read, buf.len());
            self.reader.read_exact(&mut buf[..bytes_to_read]).map(|_| {
                self.read += bytes_to_read;
                bytes_to_read
            })
        }
    }
}

pub fn temp_file() -> Result<TempFile> {
    let path = path_from_git_root(".git/objects")?;
    TempFileBuilder::new()
        .in_dir(&path)
        .prefix("gkgit")
        .build()
        .with_context(|| format!("creating temporary file in {}", path.display()))
}

pub fn path_for_object(oid: &ObjectId) -> Result<PathBuf> {
    let dir = &oid.hex[..2];
    ensure_dir(&format!(".git/objects/{dir}"))?;

    let filename = &oid.hex[2..];
    path_from_git_root(format!(".git/objects/{dir}/{filename}"))
}

pub fn write(
    mut reader: impl Read,
    size: usize,
    kind: ObjectKind,
    writer: impl Write,
) -> Result<ObjectId> {
    let mut hasher = Sha1::new();
    let mut writer = ZlibEncoder::new(writer, Compression::default());

    let header = format!("{kind} {size}\0").into_bytes();
    hasher.update(&header);

    writer.write_all(&header).context("writing header")?;

    let mut buf = [0; 4096];
    loop {
        let n = reader
            .read(&mut buf[..])
            .context("reading for hashing object")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n]).context("writing to object")?;
    }

    Ok(ObjectId::from_bytes(hasher.finalize().into()))
}

#[cfg(test)]
pub mod test {
    use io::Write;
    use temp_dir::TempDir;

    use super::*;

    pub fn init_repo() -> TempDir {
        let tmp_dir =
            TempDir::with_prefix("gkgit-test-").expect("Failed to create temporary directory");

        // Thread local storage used exclusively for testing.
        let tmp_path = tmp_dir.path().to_owned();
        TMPDIR.with_borrow_mut(|p| *p = tmp_path);

        super::init().expect("Failed to initialize repository");
        tmp_dir
    }

    pub fn write_blob_file(dir: &str, file: &str, bytes: &[u8]) {
        let tmpdir = path_from_git_root(".").expect("Failed getting path for git root");
        fs::create_dir(tmpdir.join(format!(".git/objects/{dir}")))
            .expect("Failed to create directory");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(tmpdir.join(format!(".git/objects/{dir}/{file}")))
            .expect("Failed to create blob file");
        file.write_all(bytes).expect("Failed to write blob file");
    }
}
