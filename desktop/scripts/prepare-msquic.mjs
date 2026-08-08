import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

if (process.platform === "win32") {
  const script = fileURLToPath(new URL("./prepare-msquic.ps1", import.meta.url));
  // GitHub's Windows runner drives steps with PowerShell 7, but an explicit
  // powershell.exe respawn can resolve to a stripped legacy host where
  // Get-FileHash is unavailable. Dockur/stock Windows has Windows PowerShell,
  // so retain that dependency-free fallback outside Actions.
  const powershell = process.env.GITHUB_ACTIONS === "true" ? "pwsh.exe" : "powershell.exe";
  const result = spawnSync(
    powershell,
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
    { stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
