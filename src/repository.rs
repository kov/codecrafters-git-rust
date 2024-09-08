use anyhow::Result;
use std::env;
use std::fs;
use std::io;

fn ensure_dir(path: &str) -> io::Result<()> {
    fs::create_dir(path).or_else(|e| {
        if matches!(e.kind(), io::ErrorKind::AlreadyExists) {
            Ok(())
        } else {
            Err(e)
        }
    })
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
