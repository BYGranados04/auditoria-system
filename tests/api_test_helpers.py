from pathlib import Path

from fastapi.testclient import TestClient

from app.auth.repository import AuthRepository, ScryptParameters

TEST_USERNAME = "test-user"
TEST_PASSWORD = "correct horse battery staple"
TEST_SCRYPT = ScryptParameters(n=2**10, r=8, p=1, dklen=32, maxmem=16 * 1024 * 1024)


def create_test_auth_repository(
    tmp_path: Path,
    *,
    role: str = "superadmin",
    hostnames: tuple[str, ...] | None = None,
) -> AuthRepository:
    repository = AuthRepository(
        tmp_path / "auth" / "auth.db",
        scrypt_parameters=TEST_SCRYPT,
    )
    user = repository.create_user(
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        role=role,
    )
    if role == "viewer":
        for hostname in hostnames or ("server-test",):
            registration = repository.create_agent_registration_token(int(user["id"]))
            repository.enroll_agent(
                registration_token=registration.token,
                hostname=hostname,
            )
    return repository


def login_test_user(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/auth/login",
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()
