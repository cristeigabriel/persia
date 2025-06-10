mod util;
use std::{env, io};
use util::{injector, process};

fn main() -> Result<(), io::Error> {
    println!(".~^ _persia_ i^i");
    let mut args = env::args().skip(1);
    if args.len() != 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    let Some(dll_path) = args.next() else {
        return Err(io::ErrorKind::InvalidInput.into());
    };

    use injector::inject;
    use process::ProcessIds;
    unsafe {
        inject(ProcessIds::Name("notepad.exe"), dll_path.as_str())?;
    }

    Ok(())
}
