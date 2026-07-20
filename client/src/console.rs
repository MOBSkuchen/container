//! Puts the local console into raw mode: no echo, no line buffering, Ctrl+C
//! delivered to us instead of killing the process. Keys are read as decoded
//! events elsewhere (`terminal::pump_shell`), not as bytes — a Windows
//! console byte read never yields arrows or Ctrl+C regardless of mode bits.
//! `crossterm::enable_raw_mode` doesn't set `ENABLE_VIRTUAL_TERMINAL_PROCESSING`
//! for output, so the modes are set directly here and restored on drop.

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

    /// Each half is handled independently and a non-console handle (a piped
    /// stdin/stdout) is skipped rather than treated as an error.
    pub fn enter() -> (Option<u32>, Option<u32>) {
        let Ok((input, output)) = handles() else {
            return (None, None);
        };

        let was_in = mode(input).ok().filter(|was| {
            let new = was & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
            set_mode(input, new).is_ok()
        });
        let was_out = mode(output).ok().filter(|was| {
            // Without DISABLE_NEWLINE_AUTO_RETURN a full-width line double-spaces.
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

    /// 1-based, relative to the visible window — the answer a terminal gives
    /// to `\e[6n`.
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
