use core::str;
use std::{
    ffi::CStr,
    io::{BufRead, BufReader, Write},
};

use crate::object_store::{self, ObjectId, ObjectKind};
use anyhow::{bail, Context, Result};

pub enum DisplayMode {
    Raw,
    PrettyPrint,
}

// tree object files have one or more entries in the following format:
//   <mode><whitespace><filename>\0<20 bytes hash>
// pretty printing to this:
//   <mode> <type> <hash>\t<filename>
fn print_tree(reader: &mut impl BufRead) -> Result<()> {
    let mut buf = vec![];
    let mut stdout = std::io::stdout();
    loop {
        buf.clear();

        let n = reader
            .read_until(b' ', &mut buf)
            .context("reading mode from tree object file")?;
        if n == 0 {
            return Ok(());
        }

        let mode = str::from_utf8(&buf)
            .context("mode was not valid UTF-8")?
            .trim_end();
        let kind = match mode {
            "040000" | "40000" => "tree",
            m if m.starts_with("1") => "blob",
            _ => bail!(format!("unknown mode '{mode}' reading tree object file")),
        };

        write!(stdout, "{mode:0>6} {kind} ").context("writing object type to stdout")?;

        buf.clear();
        let _ = reader
            .read_until(b'\0', &mut buf)
            .context("reading file name from tree object file")?;

        let filename = CStr::from_bytes_with_nul(&buf)
            .context("reading file name into C string")?
            .to_owned();

        buf.clear();
        buf.resize(20, 0);
        reader
            .read_exact(&mut buf[..20])
            .context("reading hash from tree object file")?;
        let hex = hex::encode(&buf);
        write!(stdout, "{hex}\t").context("writing hex to stdout")?;

        stdout
            .write_all(filename.to_bytes())
            .context("writing file name to stdout")?;

        writeln!(stdout, "").context("writing newline to stdout")?;
    }
}

fn print_raw(reader: &mut impl BufRead) -> Result<()> {
    std::io::copy(reader, &mut std::io::stdout()).context("copying raw blob contents to stdout")?;
    Ok(())
}

pub fn run(
    oid: ObjectId,
    expected_kind: Option<ObjectKind>,
    display_mode: DisplayMode,
) -> Result<()> {
    let object = object_store::read(oid)?;
    let kind = object.kind.clone();
    if let Some(expected_kind) = expected_kind {
        if !(kind == expected_kind) {
            bail!("fatal: object file exists, but is not a {expected_kind:#?}");
        }
    }

    let mut reader = BufReader::new(object);
    match display_mode {
        DisplayMode::Raw => print_raw(&mut reader),
        DisplayMode::PrettyPrint => match kind {
            ObjectKind::Blob => print_raw(&mut reader),
            ObjectKind::Tree => print_tree(&mut reader),
            ObjectKind::Commit => print_raw(&mut reader),
        },
    }
}
