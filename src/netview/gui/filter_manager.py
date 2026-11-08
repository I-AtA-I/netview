from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
)

from netview.filters import FilterSyntaxError, compile_filter
from netview.filters.saved_filters import load_saved_filters, save_saved_filters


class FilterManagerDialog(QDialog):
    filter_applied = Signal(str)

    def __init__(self, current_expression: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("NetView — Saved filters")
        self.resize(620, 460)
        self.setMinimumSize(520, 360)
        self.setStyleSheet("""
            QDialog { background: #101820; color: #e5edf2; }
            QLabel { color: #dce7ec; }
            QListWidget, QLineEdit {
                background: #121e27; color: #dce7ec;
                border: 1px solid #293943; border-radius: 7px; padding: 7px;
            }
            QPushButton {
                background: #1c3039; color: #dce7ec; border: 1px solid #344b55;
                border-radius: 7px; padding: 7px 12px; font-weight: 600;
            }
            QPushButton:hover { background: #27434b; border-color: #4d8d87; }
        """)

        try:
            self._filters = load_saved_filters()
            self._load_error = None
        except ValueError as exc:
            self._filters = []
            self._load_error = str(exc)

        root = QVBoxLayout(self)
        root.addWidget(QLabel("Saved display filters"))
        self.filter_list = QListWidget()
        self.filter_list.currentRowChanged.connect(self._load_selected)
        self.filter_list.itemDoubleClicked.connect(lambda _item: self.apply_selected())
        root.addWidget(self.filter_list, 1)

        root.addWidget(QLabel("Name"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g. HTTPS traffic")
        root.addWidget(self.name_input)
        root.addWidget(QLabel("Display filter"))
        self.expression_input = QLineEdit(current_expression)
        self.expression_input.setPlaceholderText("tcp.port == 443")
        root.addWidget(self.expression_input)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("color: #91a5b2;")
        root.addWidget(self.status_label)

        edit_row = QHBoxLayout()
        self.new_button = QPushButton("New filter")
        self.new_button.clicked.connect(self.new_filter)
        self.save_button = QPushButton("Save / update")
        self.save_button.clicked.connect(self.save_filter)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self.remove_filter)
        edit_row.addWidget(self.new_button)
        edit_row.addWidget(self.save_button)
        edit_row.addWidget(self.remove_button)
        edit_row.addStretch(1)
        root.addLayout(edit_row)

        footer = QHBoxLayout()
        footer.addStretch(1)
        self.apply_button = QPushButton("Apply selected")
        self.apply_button.clicked.connect(self.apply_selected)
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.reject)
        footer.addWidget(self.apply_button)
        footer.addWidget(self.close_button)
        root.addLayout(footer)

        self._refresh_list()
        self.remove_button.setEnabled(False)
        self.apply_button.setEnabled(False)
        if self._load_error:
            self.status_label.setText(self._load_error)
            self.status_label.setStyleSheet("color: #e18b91;")
            self.save_button.setEnabled(False)

    def new_filter(self) -> None:
        self.filter_list.setCurrentRow(-1)
        self.name_input.clear()
        self.status_label.clear()
        self.status_label.setStyleSheet("color: #91a5b2;")

    def _refresh_list(self, selected_row: int = -1) -> None:
        self.filter_list.blockSignals(True)
        self.filter_list.clear()
        for name, expression in self._filters:
            self.filter_list.addItem(f"{name}   ·   {expression}")
        if 0 <= selected_row < len(self._filters):
            self.filter_list.setCurrentRow(selected_row)
        self.filter_list.blockSignals(False)
        selected = 0 <= self.filter_list.currentRow() < len(self._filters)
        self.remove_button.setEnabled(selected)
        self.apply_button.setEnabled(selected)
        if selected:
            self._load_selected(self.filter_list.currentRow())

    def _load_selected(self, row: int) -> None:
        selected = 0 <= row < len(self._filters)
        self.remove_button.setEnabled(selected)
        self.apply_button.setEnabled(selected)
        if selected:
            name, expression = self._filters[row]
            self.name_input.setText(name)
            self.expression_input.setText(expression)

    def save_filter(self) -> None:
        name = self.name_input.text().strip()
        expression = self.expression_input.text().strip()
        if not name:
            self.status_label.setText("Enter a name for this filter.")
            return
        if not expression:
            self.status_label.setText("Enter a display filter expression.")
            return
        try:
            compile_filter(expression)
            row = self.filter_list.currentRow()
            for index, (existing_name, _existing_expression) in enumerate(self._filters):
                if existing_name.casefold() == name.casefold() and index != row:
                    raise ValueError(f"A filter named '{name}' already exists")
            if 0 <= row < len(self._filters):
                self._filters[row] = (name, expression)
            else:
                self._filters.append((name, expression))
            save_saved_filters(self._filters)
        except (FilterSyntaxError, ValueError, OSError) as exc:
            self.status_label.setText(str(exc))
            self.status_label.setStyleSheet("color: #e18b91;")
            return

        self.status_label.setStyleSheet("color: #72e0d0;")
        self.status_label.setText("Filter saved.")
        self._refresh_list(self._filters.index((name, expression)))

    def remove_filter(self) -> None:
        row = self.filter_list.currentRow()
        if not 0 <= row < len(self._filters):
            return
        self._filters.pop(row)
        try:
            save_saved_filters(self._filters)
        except OSError as exc:
            self.status_label.setText(str(exc))
            self.status_label.setStyleSheet("color: #e18b91;")
            return
        self.name_input.clear()
        self.expression_input.clear()
        self.status_label.setText("Filter removed.")
        self.status_label.setStyleSheet("color: #91a5b2;")
        self._refresh_list(min(row, len(self._filters) - 1))

    def apply_selected(self) -> None:
        row = self.filter_list.currentRow()
        if not 0 <= row < len(self._filters):
            return
        self.filter_applied.emit(self._filters[row][1])
        self.accept()
