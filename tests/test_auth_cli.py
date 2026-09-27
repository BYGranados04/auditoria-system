import sqlite3

from app.auth import __main__ as auth_cli


def test_create_superadmin_cli_uses_hidden_confirmed_password(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    minimum_password = "12345678"
    passwords = iter([minimum_password, minimum_password])
    monkeypatch.setattr("builtins.input", lambda _prompt: "cli-admin")
    monkeypatch.setattr(auth_cli.getpass, "getpass", lambda _prompt: next(passwords))
    database = tmp_path / "auth.db"

    result = auth_cli.main(["create-superadmin", "--database", str(database)])

    assert result == 0
    output = capsys.readouterr().out
    assert "Superadmin creado: cli-admin" in output
    assert minimum_password not in output
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT username, role, password_hash FROM users"
        ).fetchone()
    assert row[0:2] == ("cli-admin", "superadmin")
    assert row[2] != minimum_password.encode()
