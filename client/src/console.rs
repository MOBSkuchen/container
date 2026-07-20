//! Putting the local console into a state where it can act as a terminal
//! *emulator's* front end: output is interpreted rather than printed
//! literally, and input reaches us instead of being cooked away.
//!
//! Input is raw mode only — no echo, no line buffering, and Ctrl+C delivered
//! to us rather than killing the process. The keys themselves are *not* read
//! as bytes: a Windows console byte read only ever yields character keys
//! (arrows, F-keys and Ctrl+C never appear in the stream, whatever the mode
//! bits say — shell_probe demonstrates this), so `terminal::pump_shell` reads
//! decoded events and re-encodes them itself.
//!
//! Output needs `ENABLE_VIRTUAL_TERMINAL_PROCESSING`, which
//! `crossterm::enable_raw_mode` does not touch — hence setting the modes
//! directly and restoring exactly what was found.

use std::io;

/// Restores the console however we leave — error, panic or normal exit.
pub struct RawConsole {
    /// The modes to put back, for whichever halves we actually changed.
    #[cfg(windows)]
    restore: (Option<u32>, Option<u32>),
}

#[cfg(windows)]
mod win {
    use std::io;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{
        CONSOLE_MODE, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
        ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode,
    };

    pub fn handles() -> io::Result<(HANDLE, HANDLE)> {
        unsafe {
            let input = GetStdHandle(STD_INPUT_HANDLE);
            let output = GetStdHandle(STD_OUTPUT_HANDLE);
            if input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok((input, output))
        }
    }

    pub fn mode(handle: HANDLE) -> io::Result<u32> {
        let mut mode: CONSOLE_MODE = 0;
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(mode)
    }

    pub fn set_mode(handle: HANDLE, mode: u32) -> io::Result<()> {
        if unsafe { SetConsoleMode(handle, mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Input: no local echo, line editing or Ctrl+C processing — the remote
    /// shell does all of that. Output: interpret escape sequences, and defer
    /// the wrap at the right margin the way every terminal does (without
    /// `DISABLE_NEWLINE_AUTO_RETURN`, a full-width line double-spaces).
    ///
    /// Each half is handled independently and a non-console handle is skipped
    /// rather than treated as an error: `client shell` fed from a pipe or with
    /// its output redirected is a legitimate way to script one, and
    /// `GetConsoleMode` simply fails on a handle that is not a console.
    pub fn enter() -> (Option<u32>, Option<u32>) {
        let Ok((input, output)) = handles() else {
            return (None, None);
        };

        let was_in = mode(input).ok().filter(|was| {
            let new = was & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
            set_mode(input, new).is_ok()
        });
        let was_out = mode(output).ok().filter(|was| {
            let new = was | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
            set_mode(output, new).is_ok()
        });

        (was_in, was_out)
    }

    pub fn leave(was_in: Option<u32>, was_out: Option<u32>) {
        let Ok((input, output)) = handles() else { return };
        if let Some(was_in) = was_in {
            let _ = set_mode(input, was_in);
        }
        if let Some(was_out) = was_out {
            let _ = set_mode(output, was_out);
        }
    }

    /// Where the cursor is, 1-based and relative to the visible window — the
    /// answer a terminal gives to `\e[6n`, which the shell session answers on
    /// the console's behalf (see `terminal::pump_shell`).
    pub fn cursor_position() -> Option<(u16, u16)> {
        use windows_sys::Win32::System::Console::{
            CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo,
        };
        let (_, output) = handles().ok()?;
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetConsoleScreenBufferInfo(output, &mut info) } == 0 {
            return None;
        }
        let row = (info.dwCursorPosition.Y - info.srWindow.Top).max(0) as u16 + 1;
        let col = (info.dwCursorPosition.X - info.srWindow.Left).max(0) as u16 + 1;
        Some((row, col))
    }
}

/// The local cursor position as a terminal would report it, if there is a
/// console to ask.
#[cfg(windows)]
pub fn cursor_position() -> Option<(u16, u16)> {
    win::cursor_position()
}

impl RawConsole {
    pub fn enter() -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self { restore: win::enter() })
        }
        #[cfg(not(windows))]
        {
            // termios raw mode already delivers bytes and suppresses echo, and
            // any terminal worth using interprets escapes on output. Not being
            // a tty is not fatal here either.
            let _ = crossterm::terminal::enable_raw_mode();
            Ok(Self {})
        }
    }
}

impl Drop for RawConsole {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            let (was_in, was_out) = self.restore;
            win::leave(was_in, was_out);
        }
        #[cfg(not(windows))]
        {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}
