use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

use crate::object_store::{self, ObjectKind};
use anyhow::{Context, Result};

pub fn run(path: impl AsRef<Path>, should_write: bool) -> Result<()> {
    let reader = fs::File::open(path)?;
    let size = reader.metadata()?.size();

    if should_write {
        let tmp = object_store::temp_file()?;
        let writer = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(tmp.path())
            .with_context(|| format!("openning temporary file for writing new object file"))?;

        let oid = object_store::write(reader, size as usize, ObjectKind::Blob, writer)?;

        let final_path = object_store::path_for_object(&oid)?;
        fs::rename(tmp.path(), &final_path).with_context(|| {
            format!(
                "moving temporary file to final path {}",
                final_path.display()
            )
        })?;

        tmp.leak();

        println!("{}", oid.hex);
    } else {
        let oid = object_store::write(reader, size as usize, ObjectKind::Blob, io::sink())?;
        println!("{}", oid.hex);
    }
    Ok(())
}
