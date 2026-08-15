/// Open an http(s) URL in DockerWM Desktop if its authenticated local bridge
/// is currently reachable. `false` tells the frontend to use the configured
/// remote DockerWM fallback.
#[tauri::command]
pub async fn open_in_dockerwm(url: String) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        hf_client_core::dockerwm::open_in_running_desktop(&url)
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}
