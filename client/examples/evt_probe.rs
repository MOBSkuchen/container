//! Minimal isolation test: does `crossterm::event::EventStream` deliver
//! events (and let a `tokio::select!` keep ticking) when the process runs
//! under a ConPTY, with `RawConsole` active — no server, no socket?
//!
//! `evt_probe` (no args) spawns itself as `evt_probe child` under a pty,
//! types a few keys at it, and prints everything the child said.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use futures::StreamExt;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

#[tokio::main]
async fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("child") => child().await,
        Some("child-bytes") => child_bytes(),
        Some("child-wide") => child_wide(),
        Some("ping-test") => ping_test(),
        _ => {
            println!("==== events (crossterm) ====");
            driver("child");
            println!("==== bytes (ReadConsoleA, input cp 65001, VT input on) ====");
            driver("child-bytes");
            println!("==== wide (ReadConsoleW, no input control, VT input on) ====");
            driver("child-wide");
        }
    }
}

#[cfg(windows)]
mod rawin {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleCP, GetConsoleMode, GetStdHandle, ReadConsoleA,
        ReadConsoleW, STD_INPUT_HANDLE, SetConsoleCP, SetConsoleMode,
    };

    pub fn prepare() -> HANDLE {
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            GetConsoleMode(h, &mut mode);
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_INPUT);
            let cp = GetConsoleCP();
            SetConsoleCP(65001);
            println!("child: input cp was {cp}, mode was {mode:#x}\r");
            h
        }
    }

    pub fn read_a(h: HANDLE, buf: &mut [u8]) -> Option<usize> {
        let mut read = 0u32;
        let ok = unsafe {
            ReadConsoleA(h, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut read, std::ptr::null())
        };
        (ok != 0).then_some(read as usize)
    }

    pub fn read_w(h: HANDLE, buf: &mut [u16]) -> Option<usize> {
        let mut read = 0u32;
        let ok = unsafe {
            ReadConsoleW(h, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut read, std::ptr::null())
        };
        (ok != 0).then_some(read as usize)
    }
}

/// Raw console byte reads, the way ssh.exe-style passthrough would do it.
fn child_bytes() {
    let _console = client::console::RawConsole::enter().expect("raw console");
    #[cfg(windows)]
    {
        let h = rawin::prepare();
        let started = Instant::now();
        let mut buf = [0u8; 256];
        while started.elapsed() < Duration::from_secs(4) {
            match rawin::read_a(h, &mut buf) {
                Some(0) | None => {
                    println!("child: read failed/eof\r");
                    break;
                }
                Some(n) => println!("BYTES {:02x?}\r", &buf[..n]),
            }
        }
    }
    println!("child: done\r");
}

/// Raw wide reads with no input-control block, converted to UTF-8 by hand.
fn child_wide() {
    let _console = client::console::RawConsole::enter().expect("raw console");
    #[cfg(windows)]
    {
        let h = rawin::prepare();
        let started = Instant::now();
        let mut buf = [0u16; 256];
        while started.elapsed() < Duration::from_secs(4) {
            match rawin::read_w(h, &mut buf) {
                Some(0) | None => {
                    println!("child: read failed/eof\r");
                    break;
                }
                Some(n) => {
                    let text = String::from_utf16_lossy(&buf[..n]);
                    println!("WIDE  {:02x?} = {:?}\r", &buf[..n], text);
                }
            }
        }
    }
    println!("child: done\r");
}

async fn child() {
    println!("child: entering raw console");
    let _console = client::console::RawConsole::enter().expect("raw console");
    let mut events = crossterm::event::EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let started = Instant::now();
    let mut stdout = std::io::stdout();

    while started.elapsed() < Duration::from_secs(4) {
        tokio::select! {
            event = events.next() => {
                let _ = write!(stdout, "EVENT {event:?}\r\n");
                let _ = stdout.flush();
            }
            _ = tick.tick() => {
                let _ = write!(stdout, "TICK {}ms\r\n", started.elapsed().as_millis());
                let _ = stdout.flush();
            }
        }
    }
    let _ = write!(stdout, "child: done\r\n");
}

/// Does a bare 0x03 written into a ConPTY's input interrupt the running
/// command — and if not, does the win32-input-mode encoding of Ctrl+C?
fn ping_test() {
    // The "ignore Ctrl+C" state is inherited by children — if this harness
    // was started with it set, cmd and ping inherit it and no ^C in the
    // world interrupts anything. Clear it so the test measures ConPTY, not
    // the environment this probe happened to start from.
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 0);
    }

    let pair = native_pty_system()
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");
    let mut cmd = CommandBuilder::new("cmd.exe");
    cmd.cwd(std::env::temp_dir());
    let mut child = pair.slave.spawn_command(cmd).expect("spawn cmd");
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });

    // How much output arrives in a window, answering DSR queries as we go.
    let mut drain = |wait: Duration, writer: &mut Box<dyn Write + Send>| -> usize {
        let deadline = Instant::now() + wait;
        let mut total = 0;
        while let Ok(chunk) =
            rx.recv_timeout(deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1)))
        {
            if chunk.windows(4).any(|w| w == b"\x1b[6n") {
                let _ = writer.write_all(b"\x1b[1;1R");
                let _ = writer.flush();
            }
            total += chunk.len();
            if Instant::now() >= deadline {
                break;
            }
        }
        total
    };

    drain(Duration::from_secs(2), &mut writer);

    // Does ^C at the prompt even reach cmd as a keystroke?
    println!("[a] 0x03 at the cmd prompt, then an echo...");
    writer.write_all(b"\x03").unwrap();
    writer.flush().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    writer.write_all(b"echo still-here\r").unwrap();
    writer.flush().unwrap();
    println!("      {} bytes of reaction", drain(Duration::from_secs(2), &mut writer));

    writer.write_all(b"ping -n 30 127.0.0.1\r").unwrap();
    writer.flush().unwrap();
    drain(Duration::from_secs(3), &mut writer);

    println!("[b] bare 0x03 while ping runs...");
    writer.write_all(b"\x03").unwrap();
    writer.flush().unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let flowing = drain(Duration::from_secs(3), &mut writer);
    println!("      output in the 3s after: {flowing} bytes");

    if flowing > 0 {
        println!("[c] win32-input-mode Ctrl+C (down and up)...");
        // Vk=67 'C', Sc=46, UnicodeChar=3, KeyDown, CtrlState=LEFT_CTRL(8).
        writer.write_all(b"\x1b[67;46;3;1;8;1_\x1b[67;46;3;0;8;1_").unwrap();
        writer.flush().unwrap();
        std::thread::sleep(Duration::from_secs(2));
        let flowing = drain(Duration::from_secs(3), &mut writer);
        println!("      output in the 3s after: {flowing} bytes");

        if flowing > 0 {
            println!("[d] win32-input-mode Ctrl+Break...");
            // Vk=3 VK_CANCEL, Sc=70, no char, KeyDown, CtrlState=LEFT_CTRL(8).
            writer.write_all(b"\x1b[3;70;0;1;8;1_\x1b[3;70;0;0;8;1_").unwrap();
            writer.flush().unwrap();
            std::thread::sleep(Duration::from_secs(2));
            let flowing = drain(Duration::from_secs(3), &mut writer);
            println!("      output in the 3s after: {flowing} bytes");
        }
    }

    let _ = child.kill();
    println!("ping-test done");
}

fn driver(child_arg: &str) {
    let me = std::env::current_exe().expect("own path");
    let pair = native_pty_system()
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");
    let mut cmd = CommandBuilder::new(&me);
    cmd.arg(child_arg);
    let mut child = pair.slave.spawn_command(cmd).expect("spawn");
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");

    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });

    // Give the child a moment, then type the whole gauntlet: plain chars, an
    // arrow, Ctrl+C, an umlaut, and a CPR reply as a terminal would inject it.
    std::thread::sleep(Duration::from_millis(1000));
    for chunk in [
        b"ab".as_slice(),
        b"\x1b[A",
        b"\x03",
        "\u{fc}".as_bytes(),
        b"\x1b[18;1R",
    ] {
        writer.write_all(chunk).unwrap();
        writer.flush().unwrap();
        std::thread::sleep(Duration::from_millis(300));
    }

    let mut transcript = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1))) {
            Ok(chunk) => {
                transcript.extend_from_slice(&chunk);
                // Answer cursor-position queries like a terminal would.
                if chunk.windows(4).any(|w| w == b"\x1b[6n") {
                    let _ = writer.write_all(b"\x1b[3;1R");
                    let _ = writer.flush();
                }
            }
            Err(_) => break,
        }
        if child.try_wait().unwrap().is_some() && rx.try_recv().is_err() {
            std::thread::sleep(Duration::from_millis(200));
            while let Ok(chunk) = rx.try_recv() {
                transcript.extend_from_slice(&chunk);
            }
            break;
        }
    }
    let _ = child.kill();

    let visible = String::from_utf8_lossy(&transcript)
        .replace('\u{1b}', "\\e")
        .replace('\r', "\\r");
    println!("---- child transcript ----");
    println!("{visible}");
    println!("---- end ----");
}
