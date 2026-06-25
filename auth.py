from pathlib import Path
from typing import List, Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Full Gmail access (read, send, modify, labels) + Calendar
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar.readonly",
]


class AuthManager:
    def __init__(self, credentials_dir: Path, client_secret_path: Path):
        self.credentials_dir = Path(credentials_dir)
        self.client_secret_path = Path(client_secret_path)
        self.tokens_dir = self.credentials_dir / "tokens"
        self.tokens_dir.mkdir(parents=True, exist_ok=True)

    def get_token_path(self, account_name: str) -> Path:
        return self.tokens_dir / f"{account_name}.json"

    def get_credentials(self, account_name: str) -> Optional[Credentials]:
        token_path = self.get_token_path(account_name)
        if not token_path.exists():
            return None

        try:
            creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        except Exception:
            return None

        if creds.valid:
            return creds

        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                self._save_token(account_name, creds)
                return creds
            except Exception:
                return None

        return None

    def authenticate(self, account_name: str, email: Optional[str] = None) -> Credentials:
        if not self.client_secret_path.exists():
            raise FileNotFoundError(
                f"client_secret.json not found at {self.client_secret_path}.\n"
                "Download it from Google Cloud Console > APIs & Services > Credentials."
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            str(self.client_secret_path), SCOPES
        )

        # login_hint pre-fills the email field; prompt=select_account
        # forces account picker even if already signed in.
        kwargs: dict = {"port": 0, "prompt": "select_account"}
        if email:
            kwargs["login_hint"] = email

        creds = flow.run_local_server(**kwargs)
        self._save_token(account_name, creds)
        return creds

    def _save_token(self, account_name: str, creds: Credentials) -> None:
        token_path = self.get_token_path(account_name)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        with open(token_path, "w") as f:
            f.write(creds.to_json())

    def is_authenticated(self, account_name: str) -> bool:
        return self.get_credentials(account_name) is not None

    def list_authenticated(self) -> List[str]:
        if not self.tokens_dir.exists():
            return []
        return [p.stem for p in self.tokens_dir.glob("*.json")]
