use std::io;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    List,
    Detail,
    Form,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    None,
    Quit,
    Lock,
    Vault,
}

struct FieldInput {
    name: String,
    value: String,
    secret: bool,
}

struct Form {
    editing: Option<Uuid>,
    kind: glyx_core::ItemType,
    name: String,
    folder: String,
    tags: String,
    fields: Vec<FieldInput>,
    focus: usize,
}

struct App {
    uv: glyx_store::UnlockedVault,
    rows: Vec<glyx_store::IndexRow>,
    filtered: Vec<usize>,
    selected: usize,
    query: String,
    screen: Screen,
    detail: Option<glyx_core::Item>,
    reveal: bool,
    render: bool,
    form: Option<Form>,
    status: String,
    exit: Exit,
    pending_clear: Option<(String, std::time::Instant)>,
}

fn build_fields(kind: glyx_core::ItemType) -> Vec<FieldInput> {
    glyx_core::template::spec(kind)
        .iter()
        .map(|f| FieldInput {
            name: f.name.to_owned(),
            value: String::new(),
            secret: f.secret,
        })
        .collect()
}

fn parse_tags(text: &str) -> Vec<String> {
    let mut tags: Vec<String> = text
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    tags.dedup();
    tags
}

impl App {
    fn new(uv: glyx_store::UnlockedVault) -> Result<Self> {
        let mut app = Self {
            uv,
            rows: Vec::new(),
            filtered: Vec::new(),
            selected: 0,
            query: String::new(),
            screen: Screen::List,
            detail: None,
            reveal: false,
            render: false,
            form: None,
            status: String::new(),
            exit: Exit::None,
            pending_clear: None,
        };
        app.reload()?;
        Ok(app)
    }

    fn reload(&mut self) -> Result<()> {
        self.rows = self.uv.list(false)?;
        self.refilter();
        Ok(())
    }

    fn refilter(&mut self) {
        let q = self.query.to_lowercase();
        self.filtered = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                q.is_empty()
                    || r.name.to_lowercase().contains(&q)
                    || r.item_type.to_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    fn current_row(&self) -> Option<&glyx_store::IndexRow> {
        self.filtered
            .get(self.selected)
            .and_then(|i| self.rows.get(*i))
    }

    fn open_detail(&mut self) -> Result<()> {
        let Some(row) = self.current_row() else {
            return Ok(());
        };
        self.detail = self.uv.get_item(&row.id)?;
        self.reveal = false;
        self.render = false;
        self.screen = Screen::Detail;
        Ok(())
    }

    fn copy_first_secret(&mut self) {
        let field = {
            let Some(item) = self.detail.as_ref() else {
                return;
            };
            item.fields
                .iter()
                .find(|(k, _)| !glyx_store::present::display_value(item.item_type, k, false))
                .map(|(k, f)| (k.clone(), f.value.expose().to_owned()))
        };
        match field {
            Some((name, value)) => match glyx_autofill::clipboard::copy(&value) {
                Ok(()) => {
                    self.status = format!("{name} copied (clears in 15s)");
                    self.pending_clear = Some((
                        value,
                        std::time::Instant::now() + std::time::Duration::from_secs(15),
                    ));
                }
                Err(_) => "clipboard unavailable".clone_into(&mut self.status),
            },
            None => "no secret field on this item".clone_into(&mut self.status),
        }
    }

    fn flush_clipboard(&mut self) {
        if let Some((value, _)) = self.pending_clear.take() {
            let _ = glyx_autofill::clipboard::clear_if_ours(&value);
        }
    }

    fn clear_expired_clipboard(&mut self) {
        let due = self
            .pending_clear
            .as_ref()
            .is_some_and(|(_, deadline)| std::time::Instant::now() >= *deadline);
        if due {
            self.flush_clipboard();
            "clipboard cleared".clone_into(&mut self.status);
        }
    }

    fn show_totp(&mut self) {
        let result = {
            let Some(item) = self.detail.as_ref() else {
                return;
            };
            glyx_store::present::totp_params(item).and_then(|p| {
                glyx_crypto::totp::generate_code(&p).map_err(glyx_store::StoreError::Crypto)
            })
        };
        match result {
            Ok(code) => self.status = format!("TOTP: {code}"),
            Err(e) => self.status = format!("totp: {e}"),
        }
    }

    fn start_add(&mut self) {
        let kind = glyx_core::ItemType::Login;
        self.form = Some(Form {
            editing: None,
            kind,
            name: String::new(),
            folder: String::new(),
            tags: String::new(),
            fields: build_fields(kind),
            focus: 1,
        });
        self.screen = Screen::Form;
    }

    fn start_edit(&mut self) {
        let (id, kind, name, folder, tags, values) = {
            let Some(item) = self.detail.as_ref() else {
                return;
            };
            (
                item.id,
                item.item_type,
                item.name.clone(),
                item.folder.clone(),
                item.tags.join(", "),
                item.fields
                    .iter()
                    .map(|(k, f)| (k.clone(), f.value.expose().to_owned()))
                    .collect::<Vec<_>>(),
            )
        };
        let mut fields = build_fields(kind);
        for field in &mut fields {
            if let Some((_, value)) = values.iter().find(|(k, _)| *k == field.name) {
                field.value = value.clone();
            }
        }
        self.form = Some(Form {
            editing: Some(id),
            kind,
            name,
            folder,
            tags,
            fields,
            focus: 1,
        });
        self.screen = Screen::Form;
    }

    fn delete_current(&mut self) -> Result<()> {
        let Some(id) = self.detail.as_ref().map(|item| item.id) else {
            return Ok(());
        };
        self.uv.delete_item(&id)?;
        self.detail = None;
        self.screen = Screen::List;
        "deleted (tombstone kept for sync)".clone_into(&mut self.status);
        self.reload()
    }

    fn save_form(&mut self) -> Result<()> {
        let Some(form) = self.form.take() else {
            return Ok(());
        };
        let mut values = std::collections::BTreeMap::new();
        for f in &form.fields {
            if !f.value.is_empty() {
                values.insert(f.name.clone(), f.value.clone());
            }
        }
        if let Some(id) = form.editing {
            let mut item = self
                .uv
                .get_item(&id)?
                .ok_or_else(|| anyhow::anyhow!("item vanished"))?;
            item.name.clone_from(&form.name);
            item.folder.clone_from(&form.folder);
            item.tags = parse_tags(&form.tags);
            glyx_store::present::apply_fields(&mut self.uv, &mut item, values)?;
            self.uv.put_item(&item)?;
            self.detail = Some(item);
            self.screen = Screen::Detail;
            "saved".clone_into(&mut self.status);
        } else {
            let item = glyx_store::present::build_new(
                &mut self.uv,
                form.kind,
                form.name.clone(),
                form.folder.clone(),
                parse_tags(&form.tags),
                values,
            )?;
            let id = item.id;
            self.uv.put_item(&item)?;
            self.detail = Some(item);
            self.screen = Screen::Detail;
            self.status = format!("added {id}");
        }
        self.reload()
    }
}

fn text_input(value: &str, secret: bool, reveal: bool) -> String {
    if secret && !reveal {
        "\u{2022}".repeat(value.chars().count())
    } else {
        value.to_owned()
    }
}

fn draw_list(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());
    let search = Paragraph::new(app.query.as_str())
        .block(Block::default().borders(Borders::ALL).title("Search"));
    f.render_widget(search, chunks[0]);
    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .map(|i| {
            let row = &app.rows[*i];
            let id = row.id.as_simple().to_string();
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", &id[..8.min(id.len())]),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:<10} ", row.item_type),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(row.name.clone()),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Items"))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let mut state = ListState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(list, chunks[1], &mut state);
    let help = Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::Yellow));
    f.render_widget(help, chunks[2]);
}

fn draw_detail(f: &mut Frame, app: &App) {
    let Some(item) = app.detail.as_ref() else {
        return;
    };
    let mut lines = vec![
        Line::from(Span::styled(
            format!("{} [{}]", item.name, item_type_name(item.item_type)),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "{}  rev {}{}",
            item.id,
            item.rev,
            if item.folder.is_empty() {
                String::new()
            } else {
                format!("  folder: {}", item.folder)
            }
        )),
        Line::from(""),
    ];
    if item.item_type == glyx_core::ItemType::SshKey {
        if let Some(meta) = glyx_agent::ssh_agent::key_meta(item) {
            lines.push(Line::from(format!(
                "algorithm: {}  fingerprint: {}",
                meta.algorithm, meta.fingerprint
            )));
            lines.push(Line::from(format!(
                "agent: {}",
                if !meta.agent_supported {
                    "unsupported (export only)".to_owned()
                } else if meta.agent_enabled {
                    "enabled".to_owned()
                } else {
                    "disabled".to_owned()
                }
            )));
            if !meta.comment.is_empty() {
                lines.push(Line::from(format!("comment: {}", meta.comment)));
            }
            lines.push(Line::from(""));
        }
    }
    if item.item_type == glyx_core::ItemType::Note && app.render {
        match glyx_store::present::note_rendered(&app.uv, item, app.reveal) {
            Ok(text) => {
                for line in text.lines() {
                    lines.push(Line::from(line.to_owned()));
                }
            }
            Err(e) => lines.push(Line::from(format!("render error: {e}"))),
        }
    } else {
        for (k, f) in &item.fields {
            if item.item_type == glyx_core::ItemType::SshKey
                && matches!(k.as_str(), "agent_enabled" | "kind" | "comment")
            {
                continue;
            }
            let show = glyx_store::present::display_value(item.item_type, k, app.reveal);
            lines.push(Line::from(format!(
                "{k}: {}",
                if show {
                    f.value.expose().to_owned()
                } else {
                    "\u{2022}\u{2022}\u{2022}\u{2022}".to_owned()
                }
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "r reveal  c copy secret  t totp  m render  e edit  d delete  Esc back",
    ));
    let para = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Item"))
        .wrap(Wrap { trim: false });
    f.render_widget(para, f.area());
}

fn draw_form(f: &mut Frame, app: &App) {
    let Some(form) = app.form.as_ref() else {
        return;
    };
    let mut lines = Vec::new();
    let type_line = format!(
        "Type: {}{}",
        item_type_name(form.kind),
        if form.editing.is_none() {
            "   (Left/Right to change)"
        } else {
            ""
        }
    );
    lines.push(Line::from(type_line));
    lines.push(Line::from(format!("Name: {}", form.name)));
    lines.push(Line::from(format!("Folder: {}", form.folder)));
    lines.push(Line::from(format!("Tags: {}", form.tags)));
    for field in &form.fields {
        lines.push(Line::from(format!(
            "{}: {}",
            field.name,
            text_input(&field.value, field.secret, false)
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Tab move  Ctrl+G generate  Enter save  Esc cancel",
    ));
    let focus = form.focus.min(4 + form.fields.len());
    let mut para =
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Edit"));
    if focus >= 4 {
        para = para.scroll((u16::try_from(focus - 3).unwrap_or(0), 0));
    }
    f.render_widget(para, f.area());
}

fn draw_help(f: &mut Frame) {
    let lines = vec![
        Line::from(Span::styled(
            "glyx TUI",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("List:  type to search, Up/Down move, Enter open"),
        Line::from("       a add, v vaults, l lock & quit, q quit, ? help"),
        Line::from("Item:  r reveal, c copy secret, t totp, m render, e edit, d delete"),
        Line::from("Form:  Tab/Up/Down move, Ctrl+G generate, Enter save, Esc cancel"),
        Line::from(""),
        Line::from("Press any key to return"),
    ];
    let para = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Help"))
        .wrap(Wrap { trim: true });
    f.render_widget(para, f.area());
}

fn draw(f: &mut Frame, app: &App) {
    match app.screen {
        Screen::List => draw_list(f, app),
        Screen::Detail => draw_detail(f, app),
        Screen::Form => draw_form(f, app),
        Screen::Help => draw_help(f),
    }
}

fn item_type_name(kind: glyx_core::ItemType) -> &'static str {
    match kind {
        glyx_core::ItemType::Login => "login",
        glyx_core::ItemType::Passkey => "passkey",
        glyx_core::ItemType::Totp => "totp",
        glyx_core::ItemType::Identity => "identity",
        glyx_core::ItemType::Card => "card",
        glyx_core::ItemType::Note => "note",
        glyx_core::ItemType::File => "file",
        glyx_core::ItemType::SshKey => "ssh_key",
        glyx_core::ItemType::GenericKey => "generic_key",
        glyx_core::ItemType::Pointer => "pointer",
    }
}

fn handle_form_key(app: &mut App, key: KeyEvent) -> Result<()> {
    let Some(form) = app.form.as_mut() else {
        return Ok(());
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g') {
        if form.focus >= 4 {
            let idx = form.focus - 4;
            if let Some(field) = form.fields.get_mut(idx) {
                if field.secret {
                    if let Ok(pw) = glyx_crypto::pass::generate_password(24) {
                        field.value = pw;
                    }
                }
            }
        }
        return Ok(());
    }
    let last_focus = 4 + form.fields.len();
    match key.code {
        KeyCode::Esc => {
            app.form = None;
            app.screen = Screen::Detail;
        }
        KeyCode::Tab | KeyCode::Down => {
            form.focus = (form.focus + 1).min(last_focus);
        }
        KeyCode::BackTab | KeyCode::Up => {
            form.focus = form.focus.saturating_sub(1);
        }
        KeyCode::Left | KeyCode::Right if form.focus == 0 => {
            let all = glyx_core::template::ALL_TYPES;
            let idx = all.iter().position(|t| *t == form.kind).unwrap_or(0);
            let next = if key.code == KeyCode::Right {
                (idx + 1) % all.len()
            } else {
                (idx + all.len() - 1) % all.len()
            };
            form.kind = all[next];
            form.fields = build_fields(form.kind);
        }
        KeyCode::Enter if form.focus == last_focus => {
            app.save_form()?;
        }
        KeyCode::Backspace => match form.focus {
            0 => {}
            1 => {
                form.name.pop();
            }
            2 => {
                form.folder.pop();
            }
            3 => {
                form.tags.pop();
            }
            n => {
                if let Some(field) = form.fields.get_mut(n - 4) {
                    field.value.pop();
                }
            }
        },
        KeyCode::Char(c) => match form.focus {
            0 => {}
            1 => form.name.push(c),
            2 => form.folder.push(c),
            3 => form.tags.push(c),
            n => {
                if let Some(field) = form.fields.get_mut(n - 4) {
                    field.value.push(c);
                }
            }
        },
        _ => {}
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.exit = Exit::Quit;
        return Ok(());
    }
    match app.screen {
        Screen::Help => {
            app.screen = Screen::List;
            return Ok(());
        }
        Screen::Form => return handle_form_key(app, key),
        Screen::Detail => {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    app.screen = Screen::List;
                    app.detail = None;
                }
                KeyCode::Char('r') => app.reveal = !app.reveal,
                KeyCode::Char('c') => app.copy_first_secret(),
                KeyCode::Char('t') => app.show_totp(),
                KeyCode::Char('m') => app.render = !app.render,
                KeyCode::Char('e') => app.start_edit(),
                KeyCode::Char('d') => app.delete_current()?,
                _ => {}
            }
            return Ok(());
        }
        Screen::List => {}
    }
    match key.code {
        KeyCode::Char('q') => app.exit = Exit::Quit,
        KeyCode::Char('?') => app.screen = Screen::Help,
        KeyCode::Char('a') => app.start_add(),
        KeyCode::Char('l') => app.exit = Exit::Lock,
        KeyCode::Char('v') => app.exit = Exit::Vault,
        KeyCode::Up => app.selected = app.selected.saturating_sub(1),
        KeyCode::Down => {
            if app.selected + 1 < app.filtered.len() {
                app.selected += 1;
            }
        }
        KeyCode::Enter => app.open_detail()?,
        KeyCode::Backspace => {
            app.query.pop();
            app.refilter();
        }
        KeyCode::Char(c) => {
            app.query.push(c);
            app.refilter();
        }
        _ => {}
    }
    Ok(())
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;
        if app.exit != Exit::None {
            return Ok(());
        }
        if event::poll(std::time::Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                handle_key(app, key)?;
            }
        }
        app.clear_expired_clipboard();
    }
}

pub fn cmd_tui(ctx: &crate::Ctx) -> Result<()> {
    let uv = ctx.unlocked()?;
    let mut app = App::new(uv)?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    app.flush_clipboard();
    result?;
    let exit = app.exit;
    drop(app);
    match exit {
        Exit::Lock => crate::cmd_lock(ctx)?,
        Exit::Vault => crate::select::cmd_select(false)?,
        Exit::None | Exit::Quit => {}
    }
    Ok(())
}
