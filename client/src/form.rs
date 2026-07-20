//! A small modal form: labeled fields, one focused at a time.
//!
//! Deliberately generic enough for the instance editor, which needs
//! toggles and a retry-policy picker alongside plain text.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub enum FieldKind {
    Text { value: Vec<char>, cursor: usize },
    Toggle(bool),
    Select { options: Vec<String>, index: usize },
}

pub struct Field {
    pub label: String,
    pub kind: FieldKind,
    pub hint: Option<String>,
}

impl Field {
    pub fn text(label: impl Into<String>, initial: impl AsRef<str>) -> Self {
        let value: Vec<char> = initial.as_ref().chars().collect();
        Self {
            label: label.into(),
            kind: FieldKind::Text { cursor: value.len(), value },
            hint: None,
        }
    }

    pub fn toggle(label: impl Into<String>, initial: bool) -> Self {
        Self { label: label.into(), kind: FieldKind::Toggle(initial), hint: None }
    }

    pub fn select(label: impl Into<String>, options: Vec<String>, index: usize) -> Self {
        Self { label: label.into(), kind: FieldKind::Select { options, index }, hint: None }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn text_value(&self) -> String {
        match &self.kind {
            FieldKind::Text { value, .. } => value.iter().collect(),
            FieldKind::Toggle(b) => b.to_string(),
            FieldKind::Select { options, index } => options.get(*index).cloned().unwrap_or_default(),
        }
    }

    pub fn bool_value(&self) -> bool {
        matches!(self.kind, FieldKind::Toggle(true))
    }

    pub fn select_index(&self) -> usize {
        match &self.kind {
            FieldKind::Select { index, .. } => *index,
            _ => 0,
        }
    }
}

pub struct Form {
    pub title: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    /// Validation message from a rejected submit, cleared on the next edit
    pub error: Option<String>,
}

pub enum FormOutcome {
    Idle,
    Submit,
    Cancel,
}

impl Form {
    pub fn new(title: impl Into<String>, fields: Vec<Field>) -> Self {
        Self { title: title.into(), fields, focus: 0, error: None }
    }

    pub fn field(&self, i: usize) -> &Field {
        &self.fields[i]
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> FormOutcome {
        match key.code {
            KeyCode::Esc => return FormOutcome::Cancel,
            KeyCode::Enter => return FormOutcome::Submit,
            KeyCode::Tab | KeyCode::Down => self.move_focus(1),
            KeyCode::BackTab | KeyCode::Up => self.move_focus(-1),
            _ => {
                self.error = None;
                self.edit(key);
            }
        }
        FormOutcome::Idle
    }

    fn move_focus(&mut self, delta: isize) {
        if self.fields.is_empty() {
            return;
        }
        let len = self.fields.len() as isize;
        self.focus = (((self.focus as isize + delta) % len + len) % len) as usize;
    }

    fn edit(&mut self, key: KeyEvent) {
        let Some(field) = self.fields.get_mut(self.focus) else { return };
        match &mut field.kind {
            FieldKind::Text { value, cursor } => match key.code {
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    value.insert(*cursor, c);
                    *cursor += 1;
                }
                KeyCode::Backspace if *cursor > 0 => {
                    value.remove(*cursor - 1);
                    *cursor -= 1;
                }
                KeyCode::Delete if *cursor < value.len() => {
                    value.remove(*cursor);
                }
                KeyCode::Left => *cursor = cursor.saturating_sub(1),
                KeyCode::Right => *cursor = (*cursor + 1).min(value.len()),
                KeyCode::Home => *cursor = 0,
                KeyCode::End => *cursor = value.len(),
                _ => {}
            },
            FieldKind::Toggle(b) => {
                if matches!(key.code, KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right) {
                    *b = !*b;
                }
            }
            FieldKind::Select { options, index } => match key.code {
                KeyCode::Left => *index = if *index == 0 { options.len().saturating_sub(1) } else { *index - 1 },
                KeyCode::Right | KeyCode::Char(' ') => *index = (*index + 1) % options.len().max(1),
                _ => {}
            },
        }
    }
}
