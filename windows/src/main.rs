use tauri::{Manager, SystemTray, SystemTrayMenu, SystemTrayMenuItem};

mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let tray_menu = SystemTrayMenu::new()
        .add_item(SystemTrayMenuItem::new("Show", tauri::menu::Click::new(|_| {})))
        .add_item(SystemTrayMenuItem::new("Lock Vault", tauri::menu::Click::new(|_| {})))
        .add_item(SystemTrayMenuItem::new("Quit", tauri::menu::Click::new(|app| {
            app.exit(0);
        })));

    tauri::Builder::default()
        .system_tray(SystemTray::new().with_menu(tray_menu))
        .setup(|app| {
            let window = app.get_window("main").unwrap();
            window.set_decorations(true).unwrap();
            window.set_resizable(true).unwrap();
            window.set_title("SecureVault").unwrap();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::unlock_vault,
            commands::lock_vault,
            commands::create_vault,
            commands::add_entry,
            commands::get_entries,
            commands::delete_entry,
            commands::sync_start_discovery,
            commands::sync_get_peers,
            commands::sync_connect_peer,
            commands::sync_force_retry,
            commands::generate_password,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SecureVault");
}