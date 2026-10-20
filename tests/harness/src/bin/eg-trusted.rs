//! The process the harness policy trusts by exe path. It does what a
//! legitimate tool would: read the file, map it, hand an fd to someone, or
//! keep the secret in memory and pass it to a child through the environment.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use env_ghost_harness::{Mapping, args, send_fd};

fn main() {
    let a = args();
    match a.get(1).map(String::as_str) {
        Some("read") => {
            let b = fs::read(&a[2]).expect("read");
            std::io::stdout().write_all(&b).unwrap();
        }
        Some("mmap-read") => {
            let len = fs::metadata(&a[2]).unwrap().len() as usize;
            let m = Mapping::private(Path::new(&a[2]), len).expect("mmap");
            std::io::stdout().write_all(&m.bytes()).unwrap();
        }
        Some("send-fd") => {
            let f = fs::File::open(&a[2]).expect("open");
            let s = UnixStream::connect(&a[3]).expect("connect");
            send_fd(s.as_raw_fd(), f.as_raw_fd()).expect("sendmsg");
            let mut ack = [0u8];
            let _ = (&s).read(&mut ack);
        }
        Some("hold") => {
            // Keep the plaintext in our heap and give a child a copy in its
            // environment, like a wrapper that loads .env and execs an app.
            let secret = fs::read_to_string(&a[2]).expect("read");
            let me = std::env::current_exe().unwrap();
            let mut child = Command::new(me)
                .arg("sleep")
                .env("HELD_ENV", secret.replace('\n', ";"))
                .spawn()
                .expect("spawn");
            println!("{} {}", std::process::id(), child.id());
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            std::hint::black_box(&secret);
            let _ = child.kill();
            let _ = child.wait();
        }
        Some("sleep") => std::thread::sleep(Duration::from_secs(30)),
        _ => {
            eprintln!("usage: eg-trusted read|mmap-read|send-fd|hold|sleep ...");
            std::process::exit(2);
        }
    }
}
