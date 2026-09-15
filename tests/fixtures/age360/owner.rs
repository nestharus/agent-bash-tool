//! Same-UID hello fixture. Not independently rooted native runner ownership.
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct Owner {
    pub endpoint: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Owner {
    pub fn start(root: &Path) -> Self {
        let endpoint = root.join("completion-owner.sock");
        let listener = UnixListener::bind(&endpoint).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let path = endpoint.clone();
        let thread = std::thread::spawn(move || {
            let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
            let ticks: u64 = stat
                .rsplit_once(')')
                .unwrap()
                .1
                .split_whitespace()
                .nth(19)
                .unwrap()
                .parse()
                .unwrap();
            let identity = serde_json::json!({"pid":std::process::id(), "starttime_ticks":ticks,
                "boot_id":std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim()});
            let hello = serde_json::json!({"protocol":"completion-continuation-v2", "domain_id":"11111111-1111-4111-8111-111111111111",
                "owner_generation":"fixture", "endpoint":path, "guardian_identity":identity, "driver_identity":identity});
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                            .unwrap();
                        let mut request = [0; 6];
                        stream.read_exact(&mut request).unwrap();
                        assert_eq!(&request, b"hello\n");
                        stream.write_all(hello.to_string().as_bytes()).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(e) => panic!("fixture owner accept: {e}"),
                }
            }
        });
        Self {
            endpoint,
            stop,
            thread: Some(thread),
        }
    }
    pub fn helper() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/age360/helper.py"
        ))
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}
