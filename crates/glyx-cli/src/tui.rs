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
    form: Option<Form>,
    status: String,
    quit: bool,
    want_vault: bool,
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
            form: None,
            status: String::new(),
            quit: false,
            want_vault: false,
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
                Ok(()) => self.status = format!("{name} copied to clipboard"),
                Err(_) => "clipboard unavailable".clone_into(&mut self.status),
            },
            None => "no secret field on this item".clone_into(&mut self.status),
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
            fields: build_fields(kind),
            focus: 1,
        });
        self.screen = Screen::Form;
    }

    fn start_edit(&mut self) {
        let (id, kind, name, folder, values) = {
            let Some(item) = self.detail.as_ref() else {
                return;
            };
            (
                item.id,
                item.item_type,
                item.name.clone(),
                item.folder.clone(),
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
                Vec::new(),
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
    for (k, f) in &item.fields {
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
    lines.push(Line::from(""));
    lines.push(Line::from(
        "r reveal  c copy secret  t totp  e edit  d delete  Esc back",
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
    for field in &form.fields {
        lines.push(Line::from(format!(
            "{}: {}",
            field.name,
            text_input(&field.value, field.secret, false)
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Tab move  Enter save  Esc cancel"));
    let focus = form.focus.min(2 + form.fields.len());
    let mut para =
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Edit"));
    if focus >= 3 {
        para = para.scroll((u16::try_from(focus - 2).unwrap_or(0), 0));
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
        Line::from("Item:  r reveal, c copy secret, t totp, e edit, d delete"),
        Line::from("Form:  Tab/Up/Down move, Enter save, Esc cancel"),
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
    }
}

fn handle_form_key(app: &mut App, key: KeyEvent) -> Result<()> {
    let Some(form) = app.form.as_mut() else {
        return Ok(());
    };
    let last_focus = 2 + form.fields.len();
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
            n => {
                if let Some(field) = form.fields.get_mut(n - 3) {
                    field.value.pop();
                }
            }
        },
        KeyCode::Char(c) => match form.focus {
            0 => {}
            1 => form.name.push(c),
            2 => form.folder.push(c),
            n => {
                if let Some(field) = form.fields.get_mut(n - 3) {
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
        app.quit = true;
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
                KeyCode::Char('e') => app.start_edit(),
                KeyCode::Char('d') => app.delete_current()?,
                _ => {}
            }
            return Ok(());
        }
        Screen::List => {}
    }
    match key.code {
        KeyCode::Char('q') => app.quit = true,
        KeyCode::Char('?') => app.screen = Screen::Help,
        KeyCode::Char('a') => app.start_add(),
        KeyCode::Char('l') => {
            app.quit = true;
            "locking on exit".clone_into(&mut app.status);
        }
        KeyCode::Char('v') => {
            app.quit = true;
            app.want_vault = true;
        }
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
        if app.quit {
            return Ok(());
        }
        if event::poll(std::time::Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                handle_key(app, key)?;
            }
        }
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
    result?;
    if app.want_vault {
        crate::select::cmd_select(false)?;
    }
    Ok(())
}
