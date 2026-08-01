import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";


const projectRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const frontendPort = process.env.ARGUS_FRONTEND_PORT || "3001";
const backendPort = process.env.ARGUS_BACKEND_PORT || "8000";
const backendUrl =
  process.env.ARGUS_BACKEND_URL || `http://127.0.0.1:${backendPort}`;
const binExtension = process.platform === "win32" ? ".cmd" : "";
const vinextBin = path.join(
  projectRoot,
  "node_modules",
  ".bin",
  `vinext${binExtension}`,
);
const pythonPath = [path.join(projectRoot, "backend"), process.env.PYTHONPATH]
  .filter(Boolean)
  .join(path.delimiter);
const sharedEnv = {
  ...process.env,
  ARGUS_BACKEND_URL: backendUrl,
  PYTHONPATH: pythonPath,
  WRANGLER_LOG_PATH: path.join(projectRoot, ".wrangler", "wrangler.log"),
};

const children = [];
let stopping = false;


function launch(label, command, args) {
  const child = spawn(command, args, {
    cwd: projectRoot,
    env: sharedEnv,
    stdio: "inherit",
  });
  children.push(child);
  child.on("error", (error) => {
    console.error(`[ARGUS] ${label} 启动失败：${error.message}`);
  });
  child.on("exit", (code, signal) => {
    if (stopping) return;
    console.error(
      `[ARGUS] ${label} 已退出（${signal || `code ${code ?? 1}`}），正在停止另一项服务。`,
    );
    stopAll(code ?? 1);
  });
  return child;
}


function stopAll(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (!child.killed) child.kill("SIGTERM");
  }
  const forceTimer = setTimeout(() => {
    for (const child of children) {
      if (!child.killed) child.kill("SIGKILL");
    }
  }, 2_000);
  forceTimer.unref();
  const exitTimer = setTimeout(() => process.exit(exitCode), 2_200);
  exitTimer.unref();
}


console.log(
  `[ARGUS] 前端 http://127.0.0.1:${frontendPort} · 后端 ${backendUrl}`,
);
launch("后端", "uvicorn", [
  "argus_backend.main:app",
  "--reload",
  "--host",
  "127.0.0.1",
  "--port",
  backendPort,
]);
launch("前端", vinextBin, [
  "dev",
  "--host",
  "127.0.0.1",
  "--port",
  frontendPort,
]);

process.once("SIGINT", () => stopAll(0));
process.once("SIGTERM", () => stopAll(0));

