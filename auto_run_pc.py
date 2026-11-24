# -*- coding: utf-8 -*-
"""
Фоновый планировщик: каждые 30 минут запускает сбор и проверку VPN на локальном ПК (в РФ),
сохраняет актуальные подписки и отправляет обновлённый output/ в GitHub (strikpoo/configs).
"""

import os
import sys
import time
import shutil
import msvcrt
import argparse
import datetime
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
LOCK_FILE = BASE_DIR / "auto_run.lock"
LOG_FILE = BASE_DIR / "auto_run.log"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

OUTPUT_FILES = [
    "output/whitelist.txt",
    "output/whitelist_base64.txt",
    "output/blacklist.txt",
    "output/blacklist_base64.txt",
    "output/happ_whitelist.json",
    "output/happ_blacklist.json",
    "output/happ_whitelist.txt",
    "output/happ_whitelist_base64.txt",
]


def _rotate_log() -> None:
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 1_500_000:
            lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-500:]
            LOG_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass


def _log(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _run_cmd(args, env=None, timeout=120):
    merged_env = os.environ.copy()
    merged_env.setdefault("PYTHONUTF8", "1")
    merged_env.setdefault("PYTHONIOENCODING", "utf-8")
    if env:
        merged_env.update(env)
    return subprocess.run(
        args,
        cwd=str(BASE_DIR),
        env=merged_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=timeout,
        creationflags=NO_WINDOW,
    )


def _get_python_cli() -> str:
    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe":
        cand = exe.with_name("python.exe")
        if cand.exists():
            return str(cand)
    return str(exe)


def _is_quiet_hours(now: datetime.datetime = None) -> bool:
    """Тихое окно 23:30–07:30 (допуск 1 мин на 07:29 перед утренним запуском)."""
    now = now or datetime.datetime.now()
    hm = now.hour * 60 + now.minute
    return hm >= (23 * 60 + 30) or hm < (7 * 60 + 29)


def main() -> int:
    parser = argparse.ArgumentParser(description="Background PC runner for VPN Harvester")
    parser.add_argument("--no-git", action="store_true", help="Run harvester locally without git commit/push")
    parser.add_argument("--force", action="store_true", help="Ignore quiet hours (23:30-07:30)")
    args = parser.parse_args()

    _rotate_log()

    if not args.force and _is_quiet_hours():
        last_line = ""
        if LOG_FILE.exists():
            lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
            if lines:
                last_line = lines[-1]
        if "ночной перерыв" not in last_line:
            _log("Пропуск запуска: ночной перерыв (23:30–07:30).")
        return 0

    lock_handle = open(LOCK_FILE, "a+", encoding="utf-8")
    try:
        msvcrt.locking(lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        _log("Пропуск запуска: предыдущий цикл ещё выполняется.")
        lock_handle.close()
        return 0

    try:
        _log("=== Старт фонового обновления на ПК ===")
        py_cli = _get_python_cli()
        t0 = time.monotonic()
        res = _run_cmd([py_cli, "main.py", "--no-push"], timeout=420)
        elapsed = time.monotonic() - t0
        combined_lines = [l.strip() for l in ((res.stdout or "") + "\n" + (res.stderr or "")).splitlines() if l.strip()]
        for tail in combined_lines[-10:]:
            _log(f"  {tail}")
        if res.returncode != 0:
            err_txt = (res.stderr or "").strip()[-400:]
            _log(f"ОШИБКА main.py (код {res.returncode}) за {elapsed:.1f}с: {err_txt}")
            return res.returncode

        cache_pkl = BASE_DIR / "output" / "cache_nodes.pkl"
        cache_pkl.unlink(missing_ok=True)
        _log(f"Сборка завершена за {elapsed:.1f}с.")

        # Локальная синхронизация и публикация .docx в VK (вне Git-репозитория)
        harvester_dir = BASE_DIR.parent / "harvester"
        vk_pub = harvester_dir / "vk_publisher.py"
        if vk_pub.exists():
            harvester_out = harvester_dir / "output"
            harvester_out.mkdir(parents=True, exist_ok=True)
            for fname in OUTPUT_FILES:
                src = BASE_DIR / fname
                if src.exists():
                    shutil.copy2(src, harvester_out / src.name)
            vk_res = _run_cmd([py_cli, str(vk_pub)], env=None, timeout=60)
            vk_lines = [l.strip() for l in ((vk_res.stdout or "") + "\n" + (vk_res.stderr or "")).splitlines() if l.strip()]
            for line in vk_lines[-5:]:
                _log(f"  [VK] {line}")

        if args.no_git:
            _log("Режим --no-git: git push пропущен.")
            return 0

        git_env = {"GIT_TERMINAL_PROMPT": "0"}
        if not (BASE_DIR / ".git").exists():
            _log("Папка .git не инициализирована, пропуск git push.")
            return 1

        _run_cmd(["git", "add", "--"] + OUTPUT_FILES, env=git_env, timeout=30)
        diff_chk = _run_cmd(["git", "diff", "--cached", "--quiet"], env=git_env, timeout=30)
        if diff_chk.returncode != 0:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            c_res = _run_cmd(
                ["git", "commit", "-m", f"🚀 Auto-update from RU PC [{stamp}]"],
                env=git_env,
                timeout=30,
            )
            if c_res.returncode != 0:
                _log(f"ОШИБКА git commit: {(c_res.stderr or c_res.stdout).strip()}")
                return 1
            _log("Создан локальный коммит с обновлёнными списками.")
        else:
            _log("Изменений в output/ не было (проверим синхронизацию с GitHub).")

        _run_cmd(["git", "fetch", "origin", "main"], env=git_env, timeout=45)
        ahead_chk = _run_cmd(["git", "rev-list", "--count", "HEAD..origin/main"], env=git_env, timeout=15)
        behind_cnt = int((ahead_chk.stdout or "0").strip() or "0") if ahead_chk.returncode == 0 else 0
        if behind_cnt > 0:
            reb = _run_cmd(["git", "rebase", "-X", "theirs", "origin/main"], env=git_env, timeout=45)
            # При rebase на origin/main наши локальные коммиты — это "theirs", поэтому при конфликтах побеждает свежая сборка с ПК!
            if reb.returncode != 0:
                _run_cmd(["git", "rebase", "--abort"], env=git_env, timeout=15)
                _log(f"Предупреждение rebase: {(reb.stderr or reb.stdout).strip()[:250]}")

        unpushed_chk = _run_cmd(["git", "rev-list", "--count", "origin/main..HEAD"], env=git_env, timeout=15)
        unpushed = int((unpushed_chk.stdout or "1").strip() or "1") if unpushed_chk.returncode == 0 else 1
        if unpushed == 0:
            _log("GitHub уже актуален, push не требуется.")
            return 0

        push_res = _run_cmd(["git", "push", "origin", "main"], env=git_env, timeout=60)
        if push_res.returncode == 0:
            _log("УСПЕХ: свежие подписки отправлены в strikpoo/configs (main).")
            return 0

        err = (push_res.stderr or push_res.stdout).strip()
        _log(f"ОШИБКА git push (нужна первичная авторизация GitHub через Войти_и_отправить_на_GitHub.bat?): {err[:300]}")
        return 1
    except subprocess.TimeoutExpired as exc:
        cmd_str = " ".join(str(x) for x in (exc.cmd or []))
        _log(f"ОШИБКА таймаута ({exc.timeout}с) команды: {cmd_str}")
        return 1
    except Exception as exc:
        _log(f"НЕПРЕДВИДЕННАЯ ОШИБКА auto_run_pc: {exc}")
        return 1
    finally:
        try:
            lock_handle.seek(0)
            msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        lock_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())

