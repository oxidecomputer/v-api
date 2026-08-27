// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Interactive terminal UI for browsing sagas.
//!
//! The browser has two screens:
//!
//! - A paginated **list** of sagas. Additional pages are fetched on demand as
//!   the selection reaches the end of the currently loaded set.
//! - A **detail** view for a selected saga, with the (indented, DAG-ordered)
//!   list of nodes on the left and the events for the selected node on the
//!   right.

use std::time::Duration;

use anyhow::Result;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::cmd::saga::{
    adapter::{CliSagaAdapter, CliSagaDetail, CliSagaEvent, CliSagaSummary},
    dag::{DagNode, NodeKind, unpack_dag},
};

const INPUT_POLL: Duration = Duration::from_millis(200);

/// Rendered between the columns of a saga list row
const COLUMN_GAP: &str = "  ";

/// Upper bounds on the padded columns of the saga list.
const NAME_COLUMN_MAX: usize = 40;
const STATE_COLUMN_MAX: usize = 12;
const ID_COLUMN_MAX: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    List,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailFocus {
    Nodes,
    Events,
}

/// Run the interactive saga browser to completion.
///
/// `page_size` controls how many sagas are requested per page. When
/// `initial_id` is provided the browser opens directly on that saga's detail
/// view.
pub async fn run<A>(adapter: A, page_size: u32, initial_id: Option<String>) -> Result<()>
where
    A: CliSagaAdapter,
{
    let mut app = App::new(adapter, page_size.max(1));

    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal, initial_id).await;
    ratatui::restore();
    result
}

struct App<A: CliSagaAdapter> {
    adapter: A,
    page_size: u32,
    screen: Screen,
    status: String,
    should_quit: bool,

    // List screen state.
    sagas: Vec<A::Summary>,
    next_page: Option<String>,
    first_load_done: bool,
    end_reached: bool,
    list_state: ListState,

    // Detail screen state.
    detail: Option<A::Detail>,
    dag_nodes: Vec<DagNode>,
    node_state: ListState,
    event_scroll: u16,
    detail_focus: DetailFocus,
}

impl<A> App<A>
where
    A: CliSagaAdapter,
{
    fn new(adapter: A, page_size: u32) -> Self {
        Self {
            adapter,
            page_size,
            screen: Screen::List,
            status: String::new(),
            should_quit: false,
            sagas: Vec::new(),
            next_page: None,
            first_load_done: false,
            end_reached: false,
            list_state: ListState::default(),
            detail: None,
            dag_nodes: Vec::new(),
            node_state: ListState::default(),
            event_scroll: 0,
            detail_focus: DetailFocus::Nodes,
        }
    }

    async fn run(
        &mut self,
        terminal: &mut DefaultTerminal,
        initial_id: Option<String>,
    ) -> Result<()> {
        self.load_next_page().await;
        if let Some(id) = initial_id {
            self.open_saga(id).await;
        }

        loop {
            terminal.draw(|frame| self.render(frame))?;

            if event::poll(INPUT_POLL)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.handle_key(key.code).await;
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }

    // --- Data loading ------------------------------------------------------

    async fn load_next_page(&mut self) {
        if self.end_reached && self.first_load_done {
            return;
        }
        // For the very first load `next_page` is `None`; on subsequent loads a
        // `None` token means there are no further pages.
        if self.first_load_done && self.next_page.is_none() {
            self.end_reached = true;
            return;
        }

        let token = self.next_page.take();
        self.status = "Loading sagas…".to_string();

        match self.adapter.list_sagas(token, self.page_size).await {
            Ok(page) => {
                let fetched = page.items.len();
                self.sagas.extend(page.items);
                self.next_page = page.next_page;
                self.end_reached = self.next_page.is_none() || fetched == 0;
                self.first_load_done = true;

                if self.list_state.selected().is_none() && !self.sagas.is_empty() {
                    self.list_state.select(Some(0));
                }
                self.status.clear();
            }
            Err(err) => {
                self.first_load_done = true;
                self.status = format!("Failed to load sagas: {err}");
            }
        }
    }

    async fn open_saga(&mut self, id: String) {
        self.status = "Loading saga…".to_string();
        match self.adapter.get_saga(id).await {
            Ok(detail) => {
                self.dag_nodes = match unpack_dag(&detail.dag()) {
                    Ok(nodes) => nodes,
                    Err(err) => {
                        self.status = format!("Failed to parse saga DAG: {err}");
                        Vec::new()
                    }
                };
                self.detail = Some(detail);
                self.node_state = ListState::default();
                if !self.dag_nodes.is_empty() {
                    self.node_state.select(Some(0));
                }
                self.event_scroll = 0;
                self.detail_focus = DetailFocus::Nodes;
                self.screen = Screen::Detail;
                if !self.status.starts_with("Failed") {
                    self.status.clear();
                }
            }
            Err(err) => {
                self.status = format!("Failed to load saga: {err}");
            }
        }
    }

    // --- Input handling ----------------------------------------------------

    async fn handle_key(&mut self, code: KeyCode) {
        match self.screen {
            Screen::List => self.handle_list_key(code).await,
            Screen::Detail => self.handle_detail_key(code),
        }
    }

    async fn handle_list_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Down | KeyCode::Char('j') => self.list_next().await,
            KeyCode::Up | KeyCode::Char('k') => self.list_prev(),
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                if let Some(id) = self.selected_saga_id() {
                    self.open_saga(id).await;
                }
            }
            KeyCode::Char('n') => self.load_next_page().await,
            _ => {}
        }
    }

    fn handle_detail_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('b') => {
                self.screen = Screen::List;
            }
            KeyCode::Tab => {
                self.detail_focus = match self.detail_focus {
                    DetailFocus::Nodes => DetailFocus::Events,
                    DetailFocus::Events => DetailFocus::Nodes,
                };
            }
            KeyCode::Left | KeyCode::Char('h') => self.detail_focus = DetailFocus::Nodes,
            KeyCode::Right | KeyCode::Char('l') => self.detail_focus = DetailFocus::Events,
            KeyCode::Down | KeyCode::Char('j') => match self.detail_focus {
                DetailFocus::Nodes => self.node_next(),
                DetailFocus::Events => self.event_scroll = self.event_scroll.saturating_add(1),
            },
            KeyCode::Up | KeyCode::Char('k') => match self.detail_focus {
                DetailFocus::Nodes => self.node_prev(),
                DetailFocus::Events => self.event_scroll = self.event_scroll.saturating_sub(1),
            },
            _ => {}
        }
    }

    async fn list_next(&mut self) {
        let Some(selected) = self.list_state.selected() else {
            if !self.sagas.is_empty() {
                self.list_state.select(Some(0));
            }
            return;
        };

        if selected + 1 >= self.sagas.len() {
            // Reached the end of what we have; try to fetch more.
            if !self.end_reached {
                self.load_next_page().await;
            }
        }

        if selected + 1 < self.sagas.len() {
            self.list_state.select(Some(selected + 1));
        }
    }

    fn list_prev(&mut self) {
        if let Some(selected) = self.list_state.selected()
            && selected > 0
        {
            self.list_state.select(Some(selected - 1));
        }
    }

    fn node_next(&mut self) {
        if self.dag_nodes.is_empty() {
            return;
        }
        let next = match self.node_state.selected() {
            Some(i) if i + 1 < self.dag_nodes.len() => i + 1,
            Some(i) => i,
            None => 0,
        };
        self.node_state.select(Some(next));
        self.event_scroll = 0;
    }

    fn node_prev(&mut self) {
        let prev = match self.node_state.selected() {
            Some(i) if i > 0 => i - 1,
            _ => 0,
        };
        self.node_state.select(Some(prev));
        self.event_scroll = 0;
    }

    fn selected_saga_id(&self) -> Option<String> {
        self.list_state
            .selected()
            .and_then(|i| self.sagas.get(i))
            .map(CliSagaSummary::id)
    }

    // --- Rendering ---------------------------------------------------------

    fn render(&mut self, frame: &mut Frame) {
        match self.screen {
            Screen::List => self.render_list(frame),
            Screen::Detail => self.render_detail(frame),
        }
    }

    fn render_list(&mut self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(frame.area());

        let rows: Vec<SagaRow> = self.sagas.iter().map(SagaRow::from_summary).collect();
        let columns = ListColumns::measure(&rows);

        let items: Vec<ListItem> = rows
            .iter()
            .map(|row| {
                let line = Line::from(vec![
                    Span::styled(
                        columns.fit_name(&row.name),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(COLUMN_GAP),
                    Span::styled(columns.fit_state(&row.state), state_style(&row.state)),
                    Span::raw(COLUMN_GAP),
                    Span::styled(
                        columns.fit_id(&row.id),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(COLUMN_GAP),
                    Span::styled(row.created_at.clone(), Style::default().fg(Color::DarkGray)),
                ]);
                ListItem::new(line)
            })
            .collect();

        let more = if self.end_reached {
            ""
        } else {
            " (more available)"
        };
        let title = format!(" Sagas — {}{} ", self.sagas.len(), more);
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        frame.render_stateful_widget(list, chunks[0], &mut self.list_state);

        let help = if self.status.is_empty() {
            "↑/↓ move · enter view · n load more · q quit".to_string()
        } else {
            self.status.clone()
        };
        frame.render_widget(footer(&help), chunks[1]);
    }

    fn render_detail(&mut self, frame: &mut Frame) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(frame.area());

        // Summary header.
        if let Some(detail) = &self.detail {
            let header = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(detail.name(), Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw("  "),
                    Span::styled(detail.state(), state_style(&detail.state())),
                ]),
                Line::from(vec![
                    Span::styled("id:      ", Style::default().fg(Color::DarkGray)),
                    Span::raw(detail.id()),
                ]),
                Line::from(vec![
                    Span::styled("created: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(detail.created_at()),
                    Span::styled("   updated: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(detail.updated_at()),
                ]),
            ])
            .block(Block::default().borders(Borders::ALL).title(" Saga "));
            frame.render_widget(header, outer[0]);
        }

        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(outer[1]);

        self.render_nodes(frame, panes[0]);
        self.render_events(frame, panes[1]);

        let help = if self.status.is_empty() {
            "↑/↓ move · tab/←/→ switch pane · esc back · q quit".to_string()
        } else {
            self.status.clone()
        };
        frame.render_widget(footer(&help), outer[2]);
    }

    fn render_nodes(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items: Vec<ListItem> = self
            .dag_nodes
            .iter()
            .map(|node| {
                let indent = "  ".repeat(node.indent);
                let marker = if node.indent > 0 { "└ " } else { "" };
                let line = Line::from(vec![
                    Span::raw(format!("{indent}{marker}")),
                    Span::styled(node.label.clone(), node_style(node.kind)),
                ]);
                ListItem::new(line)
            })
            .collect();

        let focused = self.detail_focus == DetailFocus::Nodes;
        let list = List::new(items)
            .block(bordered(" Nodes ", focused))
            .highlight_style(highlight_style(focused))
            .highlight_symbol("▶ ");

        frame.render_stateful_widget(list, area, &mut self.node_state);
    }

    fn render_events(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let focused = self.detail_focus == DetailFocus::Events;

        let selected_node = self
            .node_state
            .selected()
            .and_then(|i| self.dag_nodes.get(i));

        let lines = match (selected_node, &self.detail) {
            (Some(node), Some(detail)) => {
                let events: Vec<&<A::Detail as CliSagaDetail>::Event> = detail
                    .events()
                    .iter()
                    .filter(|e| e.node_id() == node.index as i64)
                    .collect();

                if events.is_empty() {
                    vec![Line::styled(
                        "No events recorded for this node.",
                        Style::default().fg(Color::DarkGray),
                    )]
                } else {
                    let mut lines = Vec::new();
                    for event in events {
                        lines.push(Line::from(vec![
                            Span::styled(
                                event
                                    .event_type()
                                    .split_once("(")
                                    .map(|(name, _)| name.to_string())
                                    .unwrap_or(event.event_type()),
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw("  "),
                            Span::styled(event.created_at(), Style::default().fg(Color::DarkGray)),
                        ]));
                        let data = serde_json::to_string_pretty(event.event_data())
                            .unwrap_or_else(|_| event.event_data().to_string());
                        for data_line in data.lines() {
                            lines.push(Line::raw(format!("  {data_line}")));
                        }
                        lines.push(Line::raw(""));
                    }
                    lines
                }
            }
            _ => vec![Line::styled(
                "Select a node to view its events.",
                Style::default().fg(Color::DarkGray),
            )],
        };

        let title = match selected_node {
            Some(node) => format!(" Events · {} ", node.label),
            None => " Events ".to_string(),
        };

        let paragraph = Paragraph::new(lines)
            .block(bordered(&title, focused))
            .wrap(Wrap { trim: false })
            .scroll((self.event_scroll, 0));

        frame.render_widget(paragraph, area);
    }
}

/// The values rendered for a single row of the saga list, read out of a summary once so
/// that they can be measured and rendered without asking the adapter for them twice.
struct SagaRow {
    name: String,
    state: String,
    id: String,
    created_at: String,
}

impl SagaRow {
    fn from_summary<S>(summary: &S) -> Self
    where
        S: CliSagaSummary,
    {
        Self {
            name: summary.name(),
            state: summary.state(),
            id: summary.id(),
            created_at: summary.created_at(),
        }
    }
}

/// The width that each padded column of the saga list is rendered at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListColumns {
    name: usize,
    state: usize,
    id: usize,
}

impl ListColumns {
    /// Measure the columns needed to hold every loaded row. Widths grow to fit the widest
    /// value present, up to the column maximum, so that the rows of a single render always
    /// agree on where each column begins.
    fn measure(rows: &[SagaRow]) -> Self {
        let mut columns = Self {
            name: 0,
            state: 0,
            id: 0,
        };

        for row in rows {
            columns.name = columns.name.max(display_width(&row.name));
            columns.state = columns.state.max(display_width(&row.state));
            columns.id = columns.id.max(display_width(&row.id));
        }

        Self {
            name: columns.name.min(NAME_COLUMN_MAX),
            state: columns.state.min(STATE_COLUMN_MAX),
            id: columns.id.min(ID_COLUMN_MAX),
        }
    }

    fn fit_name(&self, value: &str) -> String {
        fit(value, self.name)
    }

    fn fit_state(&self, value: &str) -> String {
        fit(value, self.state)
    }

    fn fit_id(&self, value: &str) -> String {
        fit(value, self.id)
    }
}

/// The number of terminal cells that `value` occupies
fn display_width(value: &str) -> usize {
    Span::raw(value).width()
}

/// Render `value` as exactly `width` cells, padding it with spaces or truncating it with an
/// ellipsis. Values are measured in cells rather than bytes or characters so that a wide
/// character does not shift the columns that follow it.
fn fit(value: &str, width: usize) -> String {
    let value_width = display_width(value);
    if value_width <= width {
        let mut fitted = String::with_capacity(value.len() + (width - value_width));
        fitted.push_str(value);
        fitted.extend(std::iter::repeat_n(' ', width - value_width));
        return fitted;
    }

    // The ellipsis marking the truncation needs a cell of its own
    let mut fitted = String::with_capacity(value.len());
    let mut used = 0;
    let mut buf = [0u8; 4];
    for ch in value.chars() {
        let ch_width = display_width(ch.encode_utf8(&mut buf));
        if used + ch_width + 1 > width {
            break;
        }
        fitted.push(ch);
        used += ch_width;
    }

    if width > 0 {
        fitted.push('…');
        used += 1;
    }

    // A wide character may have been skipped over, leaving the row a cell short
    fitted.extend(std::iter::repeat_n(' ', width.saturating_sub(used)));
    fitted
}

fn footer(text: &str) -> Paragraph<'_> {
    Paragraph::new(Line::from(text)).style(Style::default().fg(Color::DarkGray))
}

fn bordered(title: &str, focused: bool) -> Block<'_> {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_string());
    if focused {
        block = block.border_style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
    }
    block
}

fn highlight_style(focused: bool) -> Style {
    if focused {
        Style::default()
            .bg(Color::Blue)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::REVERSED)
    }
}

fn node_style(kind: NodeKind) -> Style {
    match kind {
        NodeKind::Start | NodeKind::End => Style::default().fg(Color::DarkGray),
        NodeKind::SubsagaStart | NodeKind::SubsagaEnd => Style::default().fg(Color::Magenta),
        NodeKind::Constant => Style::default().fg(Color::Yellow),
        NodeKind::Action => Style::default(),
    }
}

fn state_style(state: &str) -> Style {
    match state.to_ascii_lowercase().as_str() {
        "done" => Style::default().fg(Color::Green),
        "running" => Style::default().fg(Color::Yellow),
        "unwinding" | "failed" => Style::default().fg(Color::Red),
        _ => Style::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::{COLUMN_GAP, ListColumns, NAME_COLUMN_MAX, SagaRow, display_width, fit};

    fn row(name: &str, state: &str, id: &str) -> SagaRow {
        SagaRow {
            name: name.to_string(),
            state: state.to_string(),
            id: id.to_string(),
            created_at: "2026-08-27T00:15:15.938481+00:00".to_string(),
        }
    }

    /// The width of the leading columns of a row, which is where the following column
    /// begins. This is the value that has to match across every row of a render.
    fn prefix_width(columns: &ListColumns, row: &SagaRow) -> usize {
        display_width(&columns.fit_name(&row.name))
            + display_width(COLUMN_GAP)
            + display_width(&columns.fit_state(&row.state))
            + display_width(COLUMN_GAP)
            + display_width(&columns.fit_id(&row.id))
            + display_width(COLUMN_GAP)
    }

    #[test]
    fn columns_fit_the_widest_value() {
        let rows = vec![
            row(
                "CaptureOpalSaga",
                "done",
                "33301d4a-7682-4d7b-a1bb-9fe8cd47cf1b",
            ),
            row(
                "BenchmarkImportSaga",
                "running",
                "99013e4d-1adb-4123-bddc-1d3402a521bc",
            ),
        ];

        let columns = ListColumns::measure(&rows);

        assert_eq!("BenchmarkImportSaga".len(), columns.name);
        assert_eq!("running".len(), columns.state);
        assert_eq!(36, columns.id);
    }

    /// Rows whose names and states differ in length must still start their later columns at
    /// the same offset
    #[test]
    fn every_row_starts_its_columns_at_the_same_offset() {
        let rows = vec![
            row(
                "CaptureOpalSaga",
                "done",
                "33301d4a-7682-4d7b-a1bb-9fe8cd47cf1b",
            ),
            row(
                "BenchmarkImportSaga",
                "running",
                "99013e4d-1adb-4123-bddc-1d3402a521bc",
            ),
            row(
                "DuroSnapshotSaga",
                "unwinding",
                "22858e12-3b5f-48c3-985d-edd132540416",
            ),
        ];

        let columns = ListColumns::measure(&rows);
        let widths = rows
            .iter()
            .map(|row| prefix_width(&columns, row))
            .collect::<Vec<_>>();

        assert!(
            widths.windows(2).all(|pair| pair[0] == pair[1]),
            "Rows disagree on where the created at column begins: {widths:?}"
        );
    }

    /// A name longer than the column cap is truncated rather than shifting the columns that
    /// follow it
    #[test]
    fn over_wide_values_are_truncated_to_the_column() {
        let long = "A".repeat(NAME_COLUMN_MAX + 20);
        let rows = vec![
            row(&long, "done", "33301d4a-7682-4d7b-a1bb-9fe8cd47cf1b"),
            row(
                "CaptureOpalSaga",
                "done",
                "33301d4a-7682-4d7b-a1bb-9fe8cd47cf1b",
            ),
        ];

        let columns = ListColumns::measure(&rows);

        assert_eq!(NAME_COLUMN_MAX, columns.name);
        let fitted = columns.fit_name(&long);
        assert_eq!(NAME_COLUMN_MAX, display_width(&fitted));
        assert!(fitted.ends_with('…'), "Truncation was not marked: {fitted}");
        assert_eq!(
            prefix_width(&columns, &rows[0]),
            prefix_width(&columns, &rows[1])
        );
    }

    /// Wide characters occupy two cells, and padding that counted characters instead would
    /// leave the following columns a cell out of place
    #[test]
    fn wide_characters_are_measured_in_cells() {
        assert_eq!(8, display_width(&fit("四字熟語", 8)));
        assert_eq!(10, display_width(&fit("四字熟語", 10)));
        assert_eq!(6, display_width(&fit("四字熟語", 6)));
    }

    #[test]
    fn short_values_are_padded_to_the_column() {
        assert_eq!("done      ", fit("done", 10));
        assert_eq!("", fit("done", 0));
    }
}
