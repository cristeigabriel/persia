mod util;
use std::{env, io};
use util::{injector, process};

fn main() -> Result<(), io::Error> {
    // Gather process execution name, process (if any), and dll path (if any)
    // If we fail, print usage string and error out
    let mut args = env::args();
    let name = args.next().unwrap();

    fn print_usage(name: &String) {
        println!("usage: {} <processs> <dll_path>\n\n", name);
    }

    let Some(process) = args.next() else {
        print_usage(&name);
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let Some(dll_path) = args.next() else {
        print_usage(&name);
        return Err(io::ErrorKind::InvalidInput.into());
    };

    let process = process.trim();
    let dll_path = dll_path.trim();

    // Try to acquire Process
    // If we fail, print error and usage
    let Some(process) = ({
        if process.chars().all(|x| x.is_ascii_digit()) {
            if let Ok(pid) = process.parse::<u32>() {
                Some(ProcessIds::Pid(pid))
            } else {
                None
            }
        } else {
            Some(ProcessIds::Name(process))
        }
    }) else {
        println!("[!] invalid process, not a valid pid or string!");
        print_usage(&name);
        return Err(io::ErrorKind::InvalidInput.into());
    };

    println!(".~^ _persia_ i^i");

    use injector::inject;
    use process::ProcessIds;
    unsafe {
        inject(process, dll_path)?;
    }

    Ok(())
}
