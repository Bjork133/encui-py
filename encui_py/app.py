from __future__ import annotations

import os
from pathlib import Path

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from encui_py.crypto_core import CryptoError, run_crypto_operation
from encui_py.widgets import ALGORITHMS, BANNER, HelpScreen


class EncuiApp(App[None]):
    """Главное TUI-приложение."""

    TITLE = "CRYPTO TUI"
    SUB_TITLE = "Conway-AES + EncUI (Cross-Platform)"
    CSS_PATH = "styles.tcss"

    BINDINGS = [
        Binding("ctrl+r", "run_action", "Выполнить", show=True),
        Binding("ctrl+s", "save_action", "Сохранить", show=True),
        Binding("ctrl+l", "load_file_action", "Загрузить файл", show=True),
        Binding("f1", "help_action", "Помощь", show=True),
        Binding("ctrl+q", "quit", "Выход", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.last_result_bytes: bytes = b""
        self.loaded_file_bytes: bytes | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(BANNER, id="banner")

        with Horizontal(id="workspace"):
            # Левая колонка: алгоритм, режим и ключи (с полной прокруткой)
            with VerticalScroll(classes="panel", id="left-panel", can_focus=True):
                yield Label("1. Алгоритм и режим", classes="section-title-first")
                yield Select(ALGORITHMS, value="conway-aes", id="algo-select", allow_blank=False)

                yield Label("Режим работы:", classes="field-label")
                with RadioSet(id="mode-set"):
                    yield RadioButton("Encrypt (шифровать)", value=True, id="mode-encrypt")
                    yield RadioButton("Decrypt (расшифровать)", id="mode-decrypt")

                yield Label("2. Параметры ключей", classes="section-title")

                # Conway-AES
                with Vertical(id="params-conway"):
                    yield Label("Public part:", classes="field-label")
                    yield Input(placeholder="Публичная часть ключа...", id="cw-public")
                    yield Label("Private part:", classes="field-label")
                    yield Input(placeholder="Приватная часть ключа...", password=True, id="cw-private")
                    yield Label("Method key (обязательно):", classes="field-label")
                    yield Input(placeholder="Ключ метода...", password=True, id="cw-method")

                # Caesar
                with Vertical(id="params-caesar", classes="hidden"):
                    yield Label("Shift (целое число, напр. 3):", classes="field-label")
                    yield Input(value="3", placeholder="0..25", id="caesar-shift")

                # Vigenere / Vernam
                with Vertical(id="params-single", classes="hidden"):
                    yield Label("Key (ключ):", classes="field-label")
                    yield Input(placeholder="Введите ключ...", id="single-key")

                # AEAD (AES-GCM / ChaCha20)
                with Vertical(id="params-aead", classes="hidden"):
                    yield Label("Key (64 hex = 32 байта):", classes="field-label")
                    yield Input(placeholder="0123456789abcdef...", id="aead-key")
                    yield Label("Nonce (24 hex = 12 байт):", classes="field-label")
                    yield Input(placeholder="00112233445566778899aabb", id="aead-nonce")
                    with Horizontal(classes="btn-row"):
                        yield Button("Сгенерировать Key + Nonce", id="btn-gen-aead")

                with Horizontal(classes="btn-row"):
                    yield Button("Выполнить [Ctrl+R]", id="btn-run", variant="success")
                    yield Button("Помощь [F1]", id="btn-help")

            # Правая колонка: вкладки ввода и результата/сохранения (обе с прокруткой)
            with Container(classes="panel", id="right-panel"):
                with TabbedContent(id="io-tabs"):
                    with TabPane("Входные данные", id="tab-input"):
                        with VerticalScroll(classes="tab-scroll", can_focus=True):
                            yield Label("Источник и формат:", classes="field-label")
                            with RadioSet(id="input-fmt-set"):
                                yield RadioButton("Текст (UTF-8)", value=True, id="fmt-utf8")
                                yield RadioButton("Hex-строка", id="fmt-hex")
                                yield RadioButton("Сырой файл", id="fmt-file")

                            with Horizontal(classes="file-row"):
                                yield Input(placeholder="Путь к файлу для загрузки...", id="load-path")
                                yield Button("Загрузить [Ctrl+L]", id="btn-load")

                            yield TextArea(id="data-input")

                            with Horizontal(classes="btn-row"):
                                yield Button("Запустить [Ctrl+R]", id="btn-run-tab", variant="success")
                                yield Button("Очистить", id="btn-clear", variant="warning")

                    with TabPane("Результат и сохранение", id="tab-output"):
                        with VerticalScroll(classes="tab-scroll", can_focus=True):
                            yield Label("Результат в Hex:", classes="field-label")
                            yield TextArea(read_only=True, id="result-hex")

                            yield Label("Предпросмотр в UTF-8:", classes="field-label")
                            yield TextArea(read_only=True, id="result-utf8")

                            with Horizontal(classes="btn-row"):
                                yield Button("Копировать Hex", id="btn-copy-hex")
                                yield Button("Результат -> Вход", id="btn-swap")

                            yield Label("Сохранение результата на диск:", classes="section-title")
                            with RadioSet(id="save-fmt-set"):
                                yield RadioButton("Бинарный (.bin)", value=True, id="save-bin")
                                yield RadioButton("Hex-текст (.hex)", id="save-hex")
                                yield RadioButton("UTF-8 текст (.txt)", id="save-utf8")

                            with Horizontal(classes="file-row"):
                                yield Input(value="output.bin", placeholder="Путь для сохранения...", id="save-path")
                                yield Button("Сохранить [Ctrl+S]", id="btn-save", variant="primary")

        yield Static("[+] Готово. Выберите алгоритм, заполните ключи и нажмите Ctrl+R.", id="status-bar")
        yield Footer()

    def set_status(self, message: str, is_error: bool = False) -> None:
        bar = self.query_one("#status-bar", Static)
        prefix = "[b red][!][/b red]" if is_error else "[b green][+][/b green]"
        bar.update(f"{prefix} {message}")

    def _collect_params(self) -> dict[str, str]:
        return {
            "public": self.query_one("#cw-public", Input).value,
            "private": self.query_one("#cw-private", Input).value,
            "method": self.query_one("#cw-method", Input).value,
            "shift": self.query_one("#caesar-shift", Input).value,
            "key": self.query_one("#single-key", Input).value,
            "aead_key": self.query_one("#aead-key", Input).value,
            "aead_nonce": self.query_one("#aead-nonce", Input).value,
        }

    def _get_input_bytes(self) -> bytes:
        if self.query_one("#fmt-file", RadioButton).value:
            if self.loaded_file_bytes is None:
                raise CryptoError("Сначала загрузите файл с диска кнопкой «Загрузить»")
            return self.loaded_file_bytes

        raw_text = self.query_one("#data-input", TextArea).text
        if self.query_one("#fmt-hex", RadioButton).value:
            cleaned = "".join(raw_text.split())
            try:
                return bytes.fromhex(cleaned)
            except ValueError as exc:
                raise CryptoError("Входные данные не являются корректной hex-строкой") from exc

        return raw_text.encode("utf-8")

    def on_descendant_focus(self, event) -> None:
        """Автоматически прокручивает левую или правую панель до активного виджета."""
        for scroll_area in self.query(VerticalScroll):
            if event.widget in scroll_area.walk_children():
                scroll_area.scroll_to_widget(event.widget, animate=False)
                break

    @on(Select.Changed, "#algo-select")
    def on_algo_changed(self, event: Select.Changed) -> None:
        algo = str(event.value)
        self.query_one("#params-conway").set_class(algo != "conway-aes", "hidden")
        self.query_one("#params-caesar").set_class(algo != "caesar", "hidden")
        self.query_one("#params-single").set_class(algo not in ("vigenere", "vernam"), "hidden")
        self.query_one("#params-aead").set_class(algo not in ("aes-gcm", "chacha20poly1305"), "hidden")
        self.set_status(f"Выбран алгоритм: [b]{algo}[/b]")

    @on(RadioSet.Changed, "#mode-set")
    def on_mode_changed(self, event: RadioSet.Changed) -> None:
        is_decrypt = event.pressed.id == "mode-decrypt"
        mode_name = "decrypt" if is_decrypt else "encrypt"
        self.set_status(f"Режим: [b]{mode_name}[/b]. Выберите формат входа (UTF-8 или Hex) перед запуском.")

    @on(RadioSet.Changed, "#save-fmt-set")
    def on_save_format_changed(self, event: RadioSet.Changed) -> None:
        path_input = self.query_one("#save-path", Input)
        current = path_input.value.strip()
        ext_map = {"save-bin": ".bin", "save-hex": ".hex", "save-utf8": ".txt"}
        new_ext = ext_map.get(event.pressed.id or "", ".bin")
        if current in ("output.bin", "output.hex", "output.txt"):
            path_input.value = f"output{new_ext}"

    @on(Button.Pressed, "#btn-gen-aead")
    def on_gen_aead(self) -> None:
        self.query_one("#aead-key", Input).value = os.urandom(32).hex()
        self.query_one("#aead-nonce", Input).value = os.urandom(12).hex()
        self.set_status("Сгенерированы случайные Key (32 Б) и Nonce (12 Б)")

    def _select_radio(self, radio_id: str) -> None:
        """Безопасно активирует RadioButton внутри RadioSet, снимая выбор с остальных."""
        target = self.query_one(f"#{radio_id}", RadioButton)
        if not target.value:
            target.toggle()

    @on(Button.Pressed, "#btn-load")
    def action_load_file_action(self) -> None:
        raw_path = self.query_one("#load-path", Input).value.strip()
        if not raw_path:
            self.set_status("Укажите путь к файлу для загрузки", is_error=True)
            return

        try:
            src = Path(raw_path).expanduser()
            if not src.exists() or not src.is_file():
                self.set_status(f"Файл не найден: {src}", is_error=True)
                return
            data = src.read_bytes()
        except OSError as exc:
            self.set_status(f"Ошибка чтения файла: {exc}", is_error=True)
            return

        self.loaded_file_bytes = data
        self._select_radio("fmt-file")
        preview = data[:256].hex() + ("..." if len(data) > 256 else "")
        self.query_one("#data-input", TextArea).text = (
            f"[Загружен файл: {src.name} | {len(data)} байт]\nHex-превью: {preview}"
        )
        self.set_status(f"Файл загружен ({len(data)} Б): {src.resolve()}")

    @on(Button.Pressed, "#btn-clear")
    def on_clear(self) -> None:
        self.query_one("#data-input", TextArea).text = ""
        self.query_one("#result-hex", TextArea).text = ""
        self.query_one("#result-utf8", TextArea).text = ""
        self.last_result_bytes = b""
        self.loaded_file_bytes = None
        if self.query_one("#fmt-file", RadioButton).value:
            self._select_radio("fmt-utf8")
        self.set_status("Поля ввода и вывода очищены")

    @on(Button.Pressed, "#btn-swap")
    def on_swap(self) -> None:
        if not self.last_result_bytes:
            self.set_status("Нет результата для переноса во вход", is_error=True)
            return
        self.loaded_file_bytes = None
        self.query_one("#data-input", TextArea).text = self.last_result_bytes.hex()
        self._select_radio("fmt-hex")
        self.query_one("#io-tabs", TabbedContent).active = "tab-input"
        self.set_status("Результат перенесён во вход (формат: Hex)")

    @on(Button.Pressed, "#btn-copy-hex")
    def on_copy_hex(self) -> None:
        if not self.last_result_bytes:
            self.set_status("Нечего копировать — сначала выполните операцию", is_error=True)
            return
        self.copy_to_clipboard(self.last_result_bytes.hex())
        self.set_status("Hex-результат скопирован в буфер обмена")

    @on(Button.Pressed, "#btn-help")
    def action_help_action(self) -> None:
        self.push_screen(HelpScreen())

    @on(Button.Pressed, "#btn-run")
    @on(Button.Pressed, "#btn-run-tab")
    def action_run_action(self) -> None:
        algo = str(self.query_one("#algo-select", Select).value)
        mode = "decrypt" if self.query_one("#mode-decrypt", RadioButton).value else "encrypt"

        try:
            raw_data = self._get_input_bytes()
            res_bytes = run_crypto_operation(
                algo=algo,
                mode=mode,
                raw_data=raw_data,
                params=self._collect_params(),
            )
        except CryptoError as exc:
            self.set_status(str(exc), is_error=True)
            return

        self.last_result_bytes = res_bytes
        self.query_one("#result-hex", TextArea).text = res_bytes.hex()
        self.query_one("#result-utf8", TextArea).text = res_bytes.decode("utf-8", errors="replace")
        self.query_one("#io-tabs", TabbedContent).active = "tab-output"

        if mode == "decrypt" and self.query_one("#save-bin", RadioButton).value:
            self._select_radio("save-utf8")

        self.set_status(f"Готово ({algo} / {mode}): {len(raw_data)} Б -> {len(res_bytes)} Б")

    @on(Button.Pressed, "#btn-save")
    def action_save_action(self) -> None:
        if not self.last_result_bytes:
            self.set_status("Нечего сохранять — сначала выполните операцию", is_error=True)
            return

        raw_path = self.query_one("#save-path", Input).value.strip()
        if not raw_path:
            self.set_status("Укажите путь для сохранения файла", is_error=True)
            return

        try:
            target = Path(raw_path).expanduser()
            if target.is_dir():
                self.set_status(f"Указанный путь является папкой: {target}", is_error=True)
                return
            target.parent.mkdir(parents=True, exist_ok=True)

            if self.query_one("#save-hex", RadioButton).value:
                target.write_text(self.last_result_bytes.hex(), encoding="utf-8")
                fmt_label = "Hex"
            elif self.query_one("#save-utf8", RadioButton).value:
                target.write_text(
                    self.last_result_bytes.decode("utf-8", errors="replace"),
                    encoding="utf-8",
                )
                fmt_label = "UTF-8"
            else:
                target.write_bytes(self.last_result_bytes)
                fmt_label = "Binary"

            self.set_status(f"Сохранено ({fmt_label}, {len(self.last_result_bytes)} Б) -> {target.resolve()}")
        except OSError as exc:
            self.set_status(f"Ошибка сохранения: {exc}", is_error=True)


def run() -> None:
    EncuiApp().run()


if __name__ == "__main__":
    run()
