from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO_REPO = ROOT / "test_repositories" / "demo_employee_portal"


def run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def commit(message: str, name: str = "Developer A", email: str = "developer@company.com") -> None:
    run(["git", "config", "user.name", name], DEMO_REPO)
    run(["git", "config", "user.email", email], DEMO_REPO)
    run(["git", "add", "."], DEMO_REPO)
    run(["git", "commit", "-m", message], DEMO_REPO)


def main() -> None:
    if DEMO_REPO.exists():
        shutil.rmtree(DEMO_REPO)
    DEMO_REPO.mkdir(parents=True)

    run(["git", "init"], DEMO_REPO)

    write(
        DEMO_REPO / "app.py",
        """def home():\n    return 'Employee Portal Running'\n""",
    )
    write(
        DEMO_REPO / "auth.py",
        """def validate_user(username, password):\n    if username == 'admin' and password == 'secure_password':\n        return True\n    return False\n""",
    )
    commit("Initial employee portal application")

    write(
        DEMO_REPO / ".env",
        """DB_HOST=localhost\nDB_USER=admin\nDB_PASSWORD=admin123\nAPI_KEY=abcd1234secret9999\n""",
    )
    commit("Added environment config")

    (DEMO_REPO / ".env").unlink()
    commit("Removed env file")

    write(
        DEMO_REPO / "auth.py",
        """def validate_user(username, password):\n    # auth validation removed temporarily\n    return True\n""",
    )
    commit("disable auth temporarily")

    # Large deletion demo.
    large_file = DEMO_REPO / "reports" / "business_rules.py"
    write(large_file, "\n".join([f"RULE_{i} = True" for i in range(150)]))
    commit("Added business rules")
    write(large_file, "RULE_1 = True\n")
    commit("temporary cleanup of business rules")

    write(DEMO_REPO / "config.json", '{"debug": true, "token": "testtoken123456789"}\n')
    commit("debug only config", name="Developer A", email="developer.a@gmail.com")

    print("Demo repository created successfully:")
    print(DEMO_REPO)


if __name__ == "__main__":
    main()
