
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) const PROFILE_IN_USE: &str = "profile-in-use";
const O_NOFOLLOW: i32 = 0x0100;

static HELD: Mutex<Option<(PathBuf, File)>> = Mutex::new(None);

pub(crate) fn lock(data: &Path) -> Result<PathBuf, String> {
    let profile = canonical(data)?;
    let mut held = HELD.lock().map_err(|_| "LokiSigner could not lock its profile")?;
    match held.as_ref() {
        Some((path, _)) if *path == profile => return Ok(profile),
        Some(_) => return Err("this LokiSigner process already opened a different profile".into()),
        None => {},
    }
    let (Some(parent), Some(name)) = (profile.parent(), profile.file_name()) else {
        return Err("LokiSigner could not lock its profile".into());
    };
    let mut lock = name.to_owned();
    lock.push(".lock");
    let failed = |e: std::io::Error| format!("LokiSigner could not lock its profile: {e}");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(O_NOFOLLOW);
    }
    let file = options.open(parent.join(lock)).map_err(failed)?;
    match file.try_lock() {
        Ok(()) => {},
        Err(std::fs::TryLockError::WouldBlock) => return Err(PROFILE_IN_USE.into()),
        Err(std::fs::TryLockError::Error(e)) => return Err(failed(e)),
    }
    *held = Some((profile.clone(), file));
    Ok(profile)
}

pub(crate) fn locked_args(args: &[String]) -> Result<Vec<String>, String> {
    let index = args.iter().position(|arg| arg == "--data").map(|i| i + 1)
        .filter(|&i| i < args.len()).ok_or("--data <dir> is required")?;
    let profile = lock(Path::new(&args[index]))?;
    let mut args = args.to_vec();
    args[index] = profile.into_os_string().into_string().map_err(|_| "LokiSigner's profile path is not valid UTF-8")?;
    Ok(args)
}

fn canonical(data: &Path) -> Result<PathBuf, String> {
    let failed = |e: std::io::Error| format!("LokiSigner could not resolve its profile folder: {e}");
    let absolute = if data.is_absolute() { data.to_owned() } else { std::env::current_dir().map_err(failed)?.join(data) };
    match absolute.canonicalize() {
        Ok(path) => Ok(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let absolute: PathBuf = absolute.components().collect();
            let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) else { return Err(failed(e)) };
            std::fs::create_dir_all(parent).map_err(failed)?;
            Ok(parent.canonicalize().map_err(failed)?.join(name))
        }
        Err(e) => Err(failed(e)),
    }
}
