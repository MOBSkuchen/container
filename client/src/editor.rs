//! Line editor for attach sessions.
//!
//! The bridge to a supervised process is line-oriented (pipes, no PTY), so the
//! remote cannot echo or edit. This editor supplies the shell feel locally:
//! cursor movement, in-line editing and history, with the terminal work left
//! to the caller — `handle` only mutates state and says what happened.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub enum Keystroke {
    /// The edit line changed; redraw it.
    Edited,
    /// A finished line to transmit (terminator included).
    Submit(String),
    /// Not an editing key.
    Ignored,
}

#[derive(Default)]
pub struct LineEditor {
    line: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// Which history entry is shown; `None` = editing a fresh line.
    browsing: Option<usize>,
    /// The fresh line, parked while browsing history.
    stash: Vec<char>,
}

impl LineEditor {
    pub fn new() -> Self {
        Self::default()
    }

    /// The line as shown. Tabs render as spaces so column = char index.
    pub fn display(&self) -> String {
        self.line.iter().map(|&c| if c == '\t' { ' ' } else { c }).collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn handle(&mut self, key: &KeyEvent) -> Keystroke {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return self.handle_ctrl(key);
        }
        match key.code {
            KeyCode::Enter => return self.submit(),
            KeyCode::Char(c) => {
                self.line.insert(self.cursor, c);
                self.cursor += 1;
            }
            KeyCode::Tab => {
                self.line.insert(self.cursor, '\t');
                self.cursor += 1;
            }
            KeyCode::Backspace => {
                if self.cursor == 0 {
                    return Keystroke::Ignored;
                }
                self.cursor -= 1;
                self.line.remove(self.cursor);
            }
            KeyCode::Delete => {
                if self.cursor == self.line.len() {
                    return Keystroke::Ignored;
                }
                self.line.remove(self.cursor);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.line.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.line.len(),
            KeyCode::Up => return self.browse(-1),
            KeyCode::Down => return self.browse(1),
            _ => return Keystroke::Ignored,
        }
        Keystroke::Edited
    }

    fn handle_ctrl(&mut self, key: &KeyEvent) -> Keystroke {
        match key.code {
            KeyCode::Char('a' | 'A') => self.cursor = 0,
            KeyCode::Char('e' | 'E') => self.cursor = self.line.len(),
            KeyCode::Char('u' | 'U') => {
                self.line.drain(..self.cursor);
                self.cursor = 0;
            }
            KeyCode::Char('k' | 'K') => {
                self.line.truncate(self.cursor);
            }
            KeyCode::Char('w' | 'W') => {
                let end = self.cursor;
                let mut start = end;
                while start > 0 && self.line[start - 1].is_whitespace() {
                    start -= 1;
                }
                while start > 0 && !self.line[start - 1].is_whitespace() {
                    start -= 1;
                }
                self.line.drain(start..end);
                self.cursor = start;
            }
            _ => return Keystroke::Ignored,
        }
        Keystroke::Edited
    }

    fn submit(&mut self) -> Keystroke {
        let text: String = std::mem::take(&mut self.line).into_iter().collect();
        self.cursor = 0;
        self.browsing = None;
        if !text.is_empty() && self.history.last() != Some(&text) {
            self.history.push(text.clone());
        }
        Keystroke::Submit(format!("{text}\r\n"))
    }

    /// Step through history; stepping below the newest entry restores the
    /// line that was being written when browsing began.
    fn browse(&mut self, delta: isize) -> Keystroke {
        let at = match (self.browsing, delta) {
            (None, d) if d < 0 && !self.history.is_empty() => {
                self.stash = std::mem::take(&mut self.line);
                self.history.len() - 1
            }
            (None, _) => return Keystroke::Ignored,
            (Some(0), d) if d < 0 => return Keystroke::Ignored,
            (Some(at), d) if d < 0 => at - 1,
            (Some(at), _) if at + 1 < self.history.len() => at + 1,
            (Some(_), _) => {
                self.browsing = None;
                self.line = std::mem::take(&mut self.stash);
                self.cursor = self.line.len();
                return Keystroke::Edited;
            }
        };
        self.browsing = Some(at);
        self.line = self.history[at].chars().collect();
        self.cursor = self.line.len();
        Keystroke::Edited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn type_str(ed: &mut LineEditor, text: &str) {
        for c in text.chars() {
            ed.handle(&press(KeyCode::Char(c)));
        }
    }

    #[test]
    fn edits_at_the_cursor() {
        let mut ed = LineEditor::new();
        type_str(&mut ed, "stop");
        ed.handle(&press(KeyCode::Home));
        ed.handle(&press(KeyCode::Delete));
        type_str(&mut ed, "ST");
        ed.handle(&press(KeyCode::End));
        ed.handle(&press(KeyCode::Backspace));
        assert_eq!(ed.display(), "STto");
    }

    #[test]
    fn submit_appends_the_terminator_and_resets() {
        let mut ed = LineEditor::new();
        type_str(&mut ed, "help");
        let Keystroke::Submit(sent) = ed.handle(&press(KeyCode::Enter)) else {
            panic!("expected a submit");
        };
        assert_eq!(sent, "help\r\n");
        assert_eq!(ed.display(), "");
        assert_eq!(ed.cursor(), 0);
    }

    #[test]
    fn history_browses_back_and_restores_the_fresh_line() {
        let mut ed = LineEditor::new();
        type_str(&mut ed, "first");
        ed.handle(&press(KeyCode::Enter));
        type_str(&mut ed, "second");
        ed.handle(&press(KeyCode::Enter));

        type_str(&mut ed, "draft");
        ed.handle(&press(KeyCode::Up));
        assert_eq!(ed.display(), "second");
        ed.handle(&press(KeyCode::Up));
        assert_eq!(ed.display(), "first");
        ed.handle(&press(KeyCode::Down));
        ed.handle(&press(KeyCode::Down));
        assert_eq!(ed.display(), "draft");
    }

    #[test]
    fn consecutive_duplicates_collapse_in_history() {
        let mut ed = LineEditor::new();
        for _ in 0..2 {
            type_str(&mut ed, "list");
            ed.handle(&press(KeyCode::Enter));
        }
        ed.handle(&press(KeyCode::Up));
        assert_eq!(ed.display(), "list");
        assert!(matches!(ed.handle(&press(KeyCode::Up)), Keystroke::Ignored));
    }

    #[test]
    fn ctrl_shortcuts_kill_and_move() {
        let mut ed = LineEditor::new();
        type_str(&mut ed, "kill two words");
        ed.handle(&ctrl('w'));
        assert_eq!(ed.display(), "kill two ");
        ed.handle(&ctrl('a'));
        assert_eq!(ed.cursor(), 0);
        ed.handle(&ctrl('k'));
        assert_eq!(ed.display(), "");
    }
}
