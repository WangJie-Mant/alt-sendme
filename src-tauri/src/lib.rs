// Library entry point for Tauri. Used by the binary (desktop) and by the native Android/iOS app (mobile).

mod commands;
mod features;
mod platform;
mod state;
#[cfg(desktop)]
mod tray;
mod version;

use commands::{
    check_launch_intent, check_path_type, check_pending_deep_link, fetch_ticket_metadata,
    focus_main_window, get_file_size, get_paths_mime_types, get_sharing_status,
    get_transport_status, receive_file, send_items, start_sharing, stop_sharing,
    toggle_context_menu,
};
use features::deep_link::{
    first_non_flag_arg, handle_deep_links, handle_deep_links_handle, DeepLinkParser,
};
use state::AppState;
use std::fs;
use std::sync::Arc;
#[cfg(desktop)]
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_deep_link::DeepLinkExt;
use tracing::debug;
pub use version::get_app_version;

use tauri::Emitter as _;
use tauri::Manager as _;

/// Clean up any orphaned .sendme-* directories from previous runs
fn cleanup_orphaned_directories() {
    let scan_dirs = vec![std::env::current_dir().ok(), Some(std::env::temp_dir())];
    for base_dir in scan_dirs.into_iter().flatten() {
        if let Ok(entries) = fs::read_dir(&base_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if (name.starts_with(".sendme-send-") || name.starts_with(".sendme-recv-"))
                        && entry.path().is_dir()
                    {
                        if let Err(e) = fs::remove_dir_all(&entry.path()) {
                            tracing::warn!("Failed to clean up orphaned directory {}: {}", name, e);
                        }
                    }
                }
            }
        }
    }
}

/// Entry point for both desktop (from main.rs) and mobile (from native app via mobile_entry_point).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default().plugin(tauri_plugin_store::Builder::new().build());

    let builder = builder.plugin(tauri_plugin_clipboard_manager::init());

    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());

    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        }

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        let mut deep_link_handled = false;

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            let parser = DeepLinkParser::new();
            for arg in &args {
                if !arg.starts_with("sendme://") {
                    continue;
                }

                match parser.parse(arg) {
                    Ok(payload) => {
                        tracing::debug!(
                            "Deep link intercepted by single-instance guard: action={}",
                            payload.action
                        );
                        let _ = app.emit("deep-link", payload);
                        deep_link_handled = true;
                        break;
                    }
                    Err(error) => {
                        let error_payload = serde_json::json!({
                            "error": error,
                            "url": arg.split('?').next().unwrap_or(arg)
                        });
                        let _ = app.emit("deep-link-error", error_payload);
                        deep_link_handled = true;
                        break;
                    }
                }
            }

            if !deep_link_handled {
                // If the second instance comes with a file path, emit it as a launch intent.
                let maybe_path = first_non_flag_arg(args.into_iter().skip(1));
                if let Some(path) = maybe_path {
                    let state = app.state::<state::LaunchIntentState>();
                    state::set_launch_intent(state.inner(), path.clone());
                    let _ = app.emit("launch-intent", path);
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let maybe_path = first_non_flag_arg(args.into_iter().skip(1));
            if let Some(path) = maybe_path {
                let state = app.state::<state::LaunchIntentState>();
                state::set_launch_intent(state.inner(), path.clone());
                let _ = app.emit("launch-intent", path);
            }
        }
    }));

    let builder = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_native_utils::init())
        .plugin(tauri_plugin_deep_link::init())
        .manage(Arc::new(std::sync::Mutex::new(
            None::<state::PendingDeepLink>,
        )))
        .manage(Arc::new(std::sync::Mutex::new(launch_intent_initial())))
        .manage(Arc::new(tokio::sync::Mutex::new(app_state_initial())))
        .invoke_handler(tauri::generate_handler![
            start_sharing,
            send_items,
            stop_sharing,
            receive_file,
            get_sharing_status,
            check_path_type,
            get_paths_mime_types,
            get_transport_status,
            get_file_size,
            focus_main_window,
            check_launch_intent,
            check_pending_deep_link,
            fetch_ticket_metadata,
            toggle_context_menu,
        ])
        .setup(|app| {
            setup_common(app);

            // Initialize deep link parser with global state
            let parser = std::sync::Arc::new(DeepLinkParser::new());

            // Handle cold start deep link
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                debug!("App launched with deep link.");
                let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
                handle_deep_links(app, &parser, urls, true);
            }

            // Handle runtime deep link
            let parser_clone = parser.clone();
            let app_handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                let urls = event.urls();
                debug!("Deep link event received, len={}", &urls.len());
                let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
                handle_deep_links_handle(&app_handle, &parser_clone, urls, false);
            });

            #[cfg(desktop)]
            start_clipboard_deep_link_watcher(app.handle().clone(), parser.clone());

            // Register deep link protocols at runtime (not supported on macOS)
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            {
                // Try to register all configured schemes; ignore errors for development
                let _ = app.deep_link().register_all();
            }

            #[cfg(all(desktop, not(target_os = "macos")))]
            tray::setup_tray(&app.handle())?;
            Ok(())
        });

    #[cfg(desktop)]
    let builder = builder.on_window_event(|window, event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            tracing::debug!("App closed to system tray");
            if let Err(e) = window.hide() {
                tracing::warn!(error = %e, "failed to hide window");
            }
        }
    });

    builder
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|_app, _event| {
            // RunEvent::Reopen only exists on macOS (dock icon re-click)
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                tray::open_and_focus(_app);
            }
        });
}

fn app_state_initial() -> AppState {
    AppState::default()
}

fn launch_intent_initial() -> Option<String> {
    first_non_flag_arg(std::env::args().skip(1))
}

#[allow(unused_variables)]
fn setup_common(app: &tauri::App) {
    cleanup_orphaned_directories();
    tracing::debug!("File drop support enabled via dragDropEnabled config");

    #[cfg(target_os = "linux")]
    if let Some(window) = app.handle().get_webview_window("main") {
        let _ = window.set_decorations(false);
    }
}

#[cfg(desktop)]
fn start_clipboard_deep_link_watcher(app_handle: tauri::AppHandle, parser: Arc<DeepLinkParser>) {
    tauri::async_runtime::spawn(async move {
        let mut last_clipboard_text: Option<String> = None;

        loop {
            let app_handle_for_read = app_handle.clone();
            let clipboard_text = tauri::async_runtime::spawn_blocking(move || {
                app_handle_for_read.clipboard().read_text()
            })
            .await;

            if let Ok(Ok(text)) = clipboard_text {
                let trimmed = text.trim().to_string();

                if trimmed.is_empty() {
                    last_clipboard_text = None;
                } else if last_clipboard_text.as_deref() != Some(trimmed.as_str()) {
                    last_clipboard_text = Some(trimmed.clone());

                    if let Ok(payload) = parser.parse(&trimmed) {
                        let is_sharing = {
                            let state = app_handle.state::<tokio::sync::Mutex<AppState>>();
                            let app_state = state.lock().await;
                            app_state.current_share.is_some() || app_state.is_share_starting
                        };

                        if !is_sharing && payload.action == "receive" && payload.ticket.is_some() {
                            if let Some(window) = app_handle.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }

                            let windows: Vec<_> =
                                app_handle.webview_windows().values().cloned().collect();
                            for window in windows {
                                let _ = window.emit("deep-link", &payload);
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        }
    });
}
