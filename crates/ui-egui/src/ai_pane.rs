//! Right-hand AI chat pane: Sign in with ChatGPT and an agent that runs GridCraft commands.
//! OAuth and network calls are native-only (`cfg(not(target_arch = "wasm32"))`).

use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use egui::{Color32, RichText, ScrollArea, Ui, vec2};
use serde_json::{Value as Json, json};

use crate::SheetApp;
use crate::theme::{self, Tokens};

#[cfg(not(target_arch = "wasm32"))]
use gridcraft_chatgpt::{AuthProgress, Credentials, FunctionCall, clear_credentials, complete_turn, list_models, load_credentials, save_credentials, sign_in};

#[derive(Clone, Debug)]
pub enum ChatRole {
    User,
    Assistant,
    System,
    Tool,
}

#[derive(Clone, Debug)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub text: String,
}

#[cfg(not(target_arch = "wasm32"))]
enum WorkerMsg {
    Auth(AuthProgress),
    Models { models: Result<Vec<(String, String)>, String>, creds: Credentials },
    Turn { result: Result<TurnResult, String>, creds: Credentials },
}

#[cfg(not(target_arch = "wasm32"))]
struct TurnResult {
    text: String,
    calls: Vec<FunctionCall>,
    continue_input: Vec<Json>,
}

/// UI + background-worker state for the AI pane.
pub struct AiState {
    pub open: bool,
    pub draft: String,
    pub messages: Vec<ChatMessage>,
    pub status: String,
    pub busy: bool,
    pub config_dir: Option<PathBuf>,
    pub model: String,
    pub models: Vec<(String, String)>,
    #[cfg(not(target_arch = "wasm32"))]
    creds: Option<Credentials>,
    #[cfg(not(target_arch = "wasm32"))]
    rx: Option<mpsc::Receiver<WorkerMsg>>,
    #[cfg(not(target_arch = "wasm32"))]
    pending_calls: Vec<FunctionCall>,
    #[cfg(not(target_arch = "wasm32"))]
    pending_continue: Vec<Json>,
}

impl Default for AiState {
    fn default() -> Self {
        Self {
            open: false,
            draft: String::new(),
            messages: Vec::new(),
            status: String::new(),
            busy: false,
            config_dir: None,
            model: String::new(),
            models: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            creds: None,
            #[cfg(not(target_arch = "wasm32"))]
            rx: None,
            #[cfg(not(target_arch = "wasm32"))]
            pending_calls: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            pending_continue: Vec::new(),
        }
    }
}

impl AiState {
    pub fn set_config_dir(&mut self, dir: PathBuf) {
        self.config_dir = Some(dir.clone());
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(Some(c)) = load_credentials(&dir) {
                self.creds = Some(c);
            }
        }
    }

    pub fn signed_in(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.creds.is_some()
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
    }

    pub fn plan_ok(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.creds.as_ref().is_some_and(|c| c.has_plan_usage())
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
    }
}

pub fn show(app: &mut SheetApp, ui: &mut Ui) {
    if !app.ai.open {
        return;
    }
    let t = Tokens::get(ui.ctx());
    egui::Panel::right("ai_chat_pane")
        .default_size(340.0)
        .resizable(true)
        .frame(egui::Frame::NONE.fill(t.ribbon).inner_margin(10.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("AI Chat").font(theme::ui_bold(15.0)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if crate::widgets::icon_button(ui, crate::icons::Icon::Close, t.text_dim, "Close", vec2(22.0, 22.0)).clicked() {
                        app.ai.open = false;
                    }
                });
            });
            ui.separator();

            #[cfg(not(target_arch = "wasm32"))]
            {
                poll_worker(app, ui.ctx());
                run_pending_tools(app);
                auth_section(app, ui);
            }
            #[cfg(target_arch = "wasm32")]
            {
                ui.label(RichText::new("Sign in with ChatGPT is available in the desktop app.").italics().color(t.text_dim));
            }

            ui.add_space(6.0);
            ui.separator();

            ScrollArea::vertical().id_salt("ai_messages").stick_to_bottom(true).max_height(ui.available_height() - 80.0).show(ui, |ui| {
                if app.ai.messages.is_empty() {
                    ui.label(RichText::new("Ask GridCraft to edit cells, build formulas, or explain the sheet.").italics().color(t.text_dim));
                }
                for m in &app.ai.messages {
                    let (label, color) = match m.role {
                        ChatRole::User => ("You", t.text),
                        ChatRole::Assistant => ("Assistant", t.accent),
                        ChatRole::System => ("System", t.text_dim),
                        ChatRole::Tool => ("Tool", Color32::from_rgb(0x10, 0x7C, 0x41)),
                    };
                    ui.label(RichText::new(label).strong().color(color).small());
                    ui.label(&m.text);
                    ui.add_space(8.0);
                }
                if app.ai.busy {
                    ui.label(RichText::new("Working…").italics().color(t.text_dim));
                    ui.ctx().request_repaint();
                }
            });

            ui.separator();
            if !app.ai.status.is_empty() {
                ui.label(RichText::new(&app.ai.status).small().color(Color32::from_rgb(0xC0, 0x00, 0x00)));
            }

            ui.horizontal(|ui| {
                let can_send = app.ai.plan_ok() && !app.ai.busy;
                let edit = ui.add_enabled(
                    can_send,
                    egui::TextEdit::multiline(&mut app.ai.draft).desired_rows(2).desired_width(ui.available_width() - 64.0).hint_text("Message…"),
                );
                let send = ui.add_enabled(can_send && !app.ai.draft.trim().is_empty(), egui::Button::new("Send"));
                let enter = edit.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter) && !i.modifiers.shift);
                if (send.clicked() || enter) && can_send {
                    let text = app.ai.draft.trim().to_string();
                    if !text.is_empty() {
                        app.ai.draft.clear();
                        send_user_message(app, text);
                    }
                }
            });
        });
}

#[cfg(not(target_arch = "wasm32"))]
fn auth_section(app: &mut SheetApp, ui: &mut Ui) {
    let t = Tokens::get(ui.ctx());
    match &app.ai.creds {
        None => {
            ui.label(RichText::new("Connect your ChatGPT account (Plus/Pro) to use the agent.").small().color(t.text_dim));
            let enabled = !app.ai.busy && app.ai.config_dir.is_some();
            if ui.add_enabled(enabled, egui::Button::new("Continue with ChatGPT")).clicked() {
                start_sign_in(app);
            }
        }
        Some(c) => {
            let email = c.email.clone().unwrap_or_else(|| "ChatGPT account".into());
            let plan = c.has_plan_usage();
            ui.horizontal(|ui| {
                ui.label(RichText::new(email).strong());
                if plan {
                    ui.label(RichText::new("· Using ChatGPT plan").small().color(Color32::from_rgb(0x10, 0x7C, 0x41)));
                } else {
                    ui.label(RichText::new("· Plan usage not granted").small().color(Color32::from_rgb(0xC0, 0x00, 0x00)));
                }
            });
            ui.horizontal(|ui| {
                if !app.ai.models.is_empty() {
                    egui::ComboBox::from_id_salt("ai_model")
                        .selected_text(app.ai.models.iter().find(|(s, _)| s == &app.ai.model).map(|(_, n)| n.as_str()).unwrap_or("Model"))
                        .show_ui(ui, |ui| {
                            for (slug, name) in app.ai.models.clone() {
                                ui.selectable_value(&mut app.ai.model, slug, name);
                            }
                        });
                } else if plan && !app.ai.busy && ui.small_button("Load models").clicked() {
                    refresh_models(app);
                }
                if ui.small_button("Manage usage").clicked() {
                    open_url(app, "https://chatgpt.com/#settings/Usage");
                }
                if ui.small_button("Sign out").clicked() {
                    if let Some(dir) = &app.ai.config_dir {
                        let _ = clear_credentials(dir);
                    }
                    app.ai.creds = None;
                    app.ai.models.clear();
                    app.ai.model.clear();
                    app.ai.status.clear();
                }
            });
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn poll_worker(app: &mut SheetApp, ctx: &egui::Context) {
    let Some(rx) = &app.ai.rx else { return };
    let mut msgs = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        msgs.push(msg);
    }
    if msgs.is_empty() {
        if app.ai.busy {
            ctx.request_repaint();
        }
        return;
    }
    for msg in msgs {
        match msg {
            WorkerMsg::Auth(AuthProgress::WaitingForBrowser) => {
                app.ai.status = "Waiting for browser sign-in…".into();
                app.ai.busy = true;
            }
            WorkerMsg::Auth(AuthProgress::Exchanging) => {
                app.ai.status = "Finishing sign-in…".into();
            }
            WorkerMsg::Auth(AuthProgress::Done(c)) => {
                app.ai.creds = Some(c);
                app.ai.status.clear();
                app.ai.busy = false;
                refresh_models(app);
            }
            WorkerMsg::Auth(AuthProgress::Failed(e)) => {
                app.ai.status = e;
                app.ai.busy = false;
            }
            WorkerMsg::Models { models, creds } => {
                app.ai.creds = Some(creds);
                app.ai.busy = false;
                match models {
                    Ok(models) => {
                        app.ai.models = models;
                        if app.ai.model.is_empty()
                            && let Some((slug, _)) = app.ai.models.first()
                        {
                            app.ai.model = slug.clone();
                        }
                        app.ai.status.clear();
                    }
                    Err(e) => app.ai.status = e,
                }
            }
            WorkerMsg::Turn { result, creds } => {
                app.ai.creds = Some(creds);
                app.ai.busy = false;
                match result {
                    Ok(turn) => {
                        if !turn.text.is_empty() {
                            app.ai.messages.push(ChatMessage { role: ChatRole::Assistant, text: turn.text });
                        }
                        if turn.calls.is_empty() {
                            app.ai.status.clear();
                        } else {
                            app.ai.pending_calls = turn.calls;
                            app.ai.pending_continue = turn.continue_input;
                            app.ai.status = "Running sheet commands…".into();
                        }
                    }
                    Err(e) => {
                        app.ai.status = e.clone();
                        app.ai.messages.push(ChatMessage { role: ChatRole::System, text: e });
                    }
                }
            }
        }
    }
    ctx.request_repaint();
}

#[cfg(not(target_arch = "wasm32"))]
fn run_pending_tools(app: &mut SheetApp) {
    if app.ai.pending_calls.is_empty() {
        return;
    }
    let calls = std::mem::take(&mut app.ai.pending_calls);
    let mut continue_input = std::mem::take(&mut app.ai.pending_continue);
    for call in &calls {
        let result = execute_tool(app, call);
        app.ai.messages.push(ChatMessage {
            role: ChatRole::Tool,
            text: format!("{} → {}", call.name, truncate(&result, 400)),
        });
        continue_input.push(json!({
            "type": "function_call_output",
            "call_id": call.call_id,
            "output": result,
        }));
    }
    start_turn(app, continue_input);
}

#[cfg(not(target_arch = "wasm32"))]
fn start_sign_in(app: &mut SheetApp) {
    let Some(dir) = app.ai.config_dir.clone() else {
        app.ai.status = "No config directory; cannot save credentials.".into();
        return;
    };
    let (tx, rx) = mpsc::channel();
    app.ai.rx = Some(rx);
    app.ai.busy = true;
    app.ai.status = "Opening browser…".into();
    sign_in(
        &dir,
        |url| open_url_fallback(url),
        {
            let tx = tx;
            let (ptx, prx) = mpsc::channel::<AuthProgress>();
            thread::spawn(move || {
                while let Ok(p) = prx.recv() {
                    if tx.send(WorkerMsg::Auth(p)).is_err() {
                        break;
                    }
                }
            });
            ptx
        },
    );
}

fn open_url(app: &SheetApp, url: &str) {
    if let Some(f) = &app.services.open_url {
        f(url);
    } else {
        open_url_fallback(url);
    }
}

fn open_url_fallback(url: &str) {
    // Windows: avoid `cmd /C start` — it either splits on bare `&` or, when quoted,
    // can treat the URL as a path (`\https://…`). `rundll32` takes the URL as one argv.
    let _ = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else if cfg!(windows) {
        std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
}

#[cfg(not(target_arch = "wasm32"))]
fn refresh_models(app: &mut SheetApp) {
    let Some(dir) = app.ai.config_dir.clone() else { return };
    let Some(mut creds) = app.ai.creds.clone() else { return };
    let (tx, rx) = mpsc::channel();
    app.ai.rx = Some(rx);
    app.ai.busy = true;
    thread::spawn(move || {
        let models = list_models(&dir, &mut creds).map_err(|e| e.to_string());
        let _ = save_credentials(&dir, &creds);
        let _ = tx.send(WorkerMsg::Models { models, creds });
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn send_user_message(app: &mut SheetApp, text: String) {
    app.ai.messages.push(ChatMessage { role: ChatRole::User, text: text.clone() });
    start_turn(app, vec![json!({"role": "user", "content": text})]);
}

#[cfg(target_arch = "wasm32")]
fn send_user_message(app: &mut SheetApp, text: String) {
    app.ai.messages.push(ChatMessage { role: ChatRole::User, text });
    app.ai.status = "AI chat requires the desktop app.".into();
}

#[cfg(not(target_arch = "wasm32"))]
fn start_turn(app: &mut SheetApp, input: Vec<Json>) {
    let Some(dir) = app.ai.config_dir.clone() else {
        app.ai.status = "No config directory.".into();
        return;
    };
    let Some(mut creds) = app.ai.creds.clone() else {
        app.ai.status = "Sign in first.".into();
        return;
    };
    let model = if app.ai.model.is_empty() { "gpt-5".to_string() } else { app.ai.model.clone() };
    let (tx, rx) = mpsc::channel();
    app.ai.rx = Some(rx);
    app.ai.busy = true;
    app.ai.status.clear();
    thread::spawn(move || {
        let result = complete_turn(&dir, &mut creds, &model, &input).map(|out| {
            let mut continue_input = input;
            for c in &out.function_calls {
                continue_input.push(json!({
                    "type": "function_call",
                    "call_id": c.call_id,
                    "name": c.name,
                    "arguments": c.arguments,
                }));
            }
            let _ = save_credentials(&dir, &creds);
            TurnResult { text: out.text, calls: out.function_calls, continue_input }
        });
        let _ = tx.send(WorkerMsg::Turn { result: result.map_err(|e| e.to_string()), creds });
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn execute_tool(app: &mut SheetApp, call: &FunctionCall) -> String {
    let args: Json = serde_json::from_str(&call.arguments).unwrap_or(json!({}));
    match call.name.as_str() {
        "execute_command" => {
            let cmd = args.get("command").and_then(|c| c.as_str()).unwrap_or("");
            if cmd.is_empty() {
                return "error: missing command".into();
            }
            let params = args.get("params").cloned().unwrap_or(json!({}));
            match app.run(cmd, params) {
                Ok(v) => v.to_string(),
                Err(e) => format!("error: {e}"),
            }
        }
        "list_commands" => {
            let search = args.get("search").cloned().unwrap_or(Json::Null);
            match app.session.run("app.commands", json!({"search": search})) {
                Ok(v) => truncate(&v.to_string(), 8000),
                Err(e) => format!("error: {e}"),
            }
        }
        "inspect_workbook" => match app.session.run("document.inspect", json!({})) {
            Ok(v) => truncate(&v.to_string(), 8000),
            Err(e) => format!("error: {e}"),
        },
        "read_range" => match app.session.run("sheet.read", args) {
            Ok(v) => truncate(&v.to_string(), 8000),
            Err(e) => format!("error: {e}"),
        },
        other => format!("error: unknown tool {other}"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}
