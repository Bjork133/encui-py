from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

BANNER = r"""
         __   __     _          _____      _ 
  ___ _ _\ \ / / __ | |_ ___   |_   _|   _(_)
 / __| '__\ V / '_ \| __/ _ \    | || | | | |
| (__| |   | || |_) | || (_) |   | || |_| | |
 \___|_|   |_|| .__/ \__\___/    |_| \__,_|_|
              |_| [Bjork133's encui adaptation]
"""

ALGORITHMS: list[tuple[str, str]] = [
    ("Conway-AES (public / private / method)", "conway-aes"),
    ("Caesar (shift)", "caesar"),
    ("Vigenere (key)", "vigenere"),
    ("Vernam / OTP (key >= data)", "vernam"),
    ("AES-256-GCM (key + nonce hex)", "aes-gcm"),
    ("ChaCha20-Poly1305 (key + nonce hex)", "chacha20poly1305"),
]


class HelpScreen(ModalScreen[None]):
    """Модальное окно справки."""

    BINDINGS = [
        Binding("escape", "dismiss", "Закрыть"),
        Binding("q", "dismiss", "Закрыть"),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="help-dialog"):
            yield Label("Справка по CRYPTO TUI", id="help-title")
            yield Static(
                "1. [b]Алгоритм и режим[/b] — выберите шифр и режим (Encrypt / Decrypt).\n"
                "2. [b]Ключи[/b] — заполните параметры для выбранного алгоритма.\n"
                "3. [b]Входные данные[/b] — введите текст/Hex или загрузите файл с диска.\n"
                "4. [b]Результат[/b] — скопируйте Hex или сохраните в .bin, .hex, .txt.\n\n"
                "[b]Клавиши:[/b] Ctrl+R — запуск, Ctrl+S — сохранить, Ctrl+L — файл, F1 — помощь.",
                id="help-body",
            )
            yield Button("Закрыть [Esc]", variant="primary", id="close-help")

    @on(Button.Pressed, "#close-help")
    def on_close(self) -> None:
        self.dismiss()
