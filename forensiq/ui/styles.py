"""
ForensIQ dark theme — applied globally via app.setStyleSheet().
"""

STYLESHEET = """
/* ── Base ── */
QMainWindow, QDialog {
    background-color: #0D1117;
}

/* ── Ensure dialog content area is always dark ── */
QDialog QWidget {
    background-color: #0D1117;
}
QDialog QFrame#card {
    background-color: #161B22;
    border: 1px solid #21262D;
}
QWidget {
    background-color: transparent;
    color: #E6EDF3;
    font-family: 'Segoe UI', 'SF Pro Display', Arial, sans-serif;
    font-size: 13px;
}

/* ── Sidebar ── */
#sidebar {
    background-color: #161B22;
    border-right: 1px solid #21262D;
    min-width: 200px;
    max-width: 200px;
}
#sidebar QPushButton {
    background: transparent;
    border: none;
    border-radius: 6px;
    padding: 9px 16px;
    text-align: left;
    color: #8B949E;
    font-size: 13px;
    font-weight: 500;
}
#sidebar QPushButton:hover {
    background-color: #21262D;
    color: #E6EDF3;
}
#sidebar QPushButton[active="true"] {
    background-color: #1D9E7522;
    color: #1D9E75;
}

/* ── Header / Top bar ── */
#header {
    background-color: #161B22;
    border-bottom: 1px solid #21262D;
}

/* ── Content panels ── */
#contentPanel {
    background-color: #0D1117;
}

/* ── Cards / Panels ── */
#card {
    background-color: #161B22;
    border: 1px solid #21262D;
    border-radius: 8px;
}

/* ── Labels ── */
QLabel {
    background: transparent;
}
QLabel#sectionTitle {
    font-size: 18px;
    font-weight: 600;
    color: #E6EDF3;
}
QLabel#metaLabel {
    color: #8B949E;
    font-size: 12px;
    /* word-wrap cannot be set in QSS — use setWordWrap(True) in code for long text */
}
QLabel#tealAccent {
    color: #1D9E75;
    font-weight: 600;
}
QLabel#dangerLabel {
    color: #F85149;
}
QLabel#warnLabel {
    color: #E3B341;
}
QLabel#successLabel {
    color: #3FB950;
}

/* ── Buttons ── */
QPushButton {
    background-color: #21262D;
    color: #E6EDF3;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #30363D;
    border-color: #484F58;
}
QPushButton:pressed {
    background-color: #161B22;
}
QPushButton#primaryBtn {
    background-color: #1D9E75;
    border: none;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#primaryBtn:hover {
    background-color: #17856A;
}
QPushButton#primaryBtn:pressed {
    background-color: #136358;
}
QPushButton#dangerBtn {
    background-color: #6E1A1A;
    border-color: #F85149;
    color: #F85149;
}
QPushButton#dangerBtn:hover {
    background-color: #8B2020;
}
QPushButton:disabled {
    background-color: #161B22;
    color: #484F58;
    border-color: #21262D;
}

/* ── Tables ── */
QTableWidget {
    background-color: #161B22;
    alternate-background-color: #1C2128;
    border: 1px solid #21262D;
    border-radius: 8px;
    gridline-color: #21262D;
    selection-background-color: #1D9E7530;
    selection-color: #E6EDF3;
}
QTableWidget::item {
    padding: 5px 10px;
    min-height: 26px;
    border: none;
}
QTableWidget::item:selected {
    background-color: #1D9E7530;
    color: #E6EDF3;
}
QHeaderView::section {
    background-color: #21262D;
    color: #8B949E;
    border: none;
    border-right: 1px solid #30363D;
    border-bottom: 1px solid #30363D;
    padding: 7px 10px;
    min-height: 32px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

/* ── Input fields ── */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #161B22;
    color: #E6EDF3;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 7px 10px;
    selection-background-color: #1D9E7560;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #1D9E75;
    outline: none;
}
QLineEdit::placeholder {
    color: #484F58;
}

/* ── ComboBox ── */
QComboBox {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 6px 10px;
    color: #E6EDF3;
}
QComboBox:focus { border-color: #1D9E75; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background-color: #161B22;
    border: 1px solid #30363D;
    selection-background-color: #1D9E7530;
    color: #E6EDF3;
}

/* ── CheckBoxes ── */
QCheckBox {
    spacing: 8px;
    color: #E6EDF3;
}
QCheckBox::indicator {
    width: 16px; height: 16px;
    border-radius: 4px;
    border: 1px solid #484F58;
    background: #161B22;
}
QCheckBox::indicator:checked {
    background-color: #1D9E75;
    border-color: #1D9E75;
}

/* ── Progress bar ── */
QProgressBar {
    background-color: #21262D;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background-color: #1D9E75;
    border-radius: 4px;
}

/* ── Tab widget ── */
QTabWidget::pane {
    background-color: #161B22;
    border: 1px solid #21262D;
    border-radius: 0 8px 8px 8px;
}
QTabBar::tab {
    background-color: #0D1117;
    color: #8B949E;
    border: 1px solid #21262D;
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    padding: 7px 16px;
    margin-right: 3px;
    font-size: 12px;
    min-width: 80px;
}
QTabBar::tab:selected {
    background-color: #161B22;
    color: #1D9E75;
    border-bottom: 2px solid #1D9E75;
}
QTabBar::tab:hover:!selected {
    background-color: #161B22;
    color: #E6EDF3;
}

/* ── Scroll bars ── */
QScrollBar:vertical {
    background: #0D1117;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #30363D;
    border-radius: 4px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #484F58; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }

QScrollBar:horizontal {
    background: #0D1117;
    height: 8px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #30363D;
    border-radius: 4px;
    min-width: 30px;
}
QScrollBar::handle:horizontal:hover { background: #484F58; }

/* ── Splitter ── */
QSplitter::handle {
    background: #21262D;
}
QSplitter::handle:horizontal { width: 1px; }
QSplitter::handle:vertical { height: 1px; }

/* ── GroupBox ── */
QGroupBox {
    border: 1px solid #21262D;
    border-radius: 8px;
    margin-top: 12px;
    padding: 8px;
    color: #8B949E;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}

/* ── Tooltips ── */
QToolTip {
    background-color: #161B22;
    color: #E6EDF3;
    border: 1px solid #30363D;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}

/* ── Status bar ── */
QStatusBar {
    background-color: #161B22;
    border-top: 1px solid #21262D;
    color: #8B949E;
    font-size: 12px;
}

/* ── Menu ── */
QMenuBar { background-color: #161B22; border-bottom: 1px solid #21262D; }
QMenuBar::item { padding: 6px 12px; color: #8B949E; }
QMenuBar::item:selected { background: #21262D; color: #E6EDF3; }
QMenu { background-color: #161B22; border: 1px solid #30363D; border-radius: 8px; }
QMenu::item { padding: 8px 24px; color: #E6EDF3; }
QMenu::item:selected { background-color: #1D9E7530; color: #E6EDF3; }
QMenu::separator { height: 1px; background: #21262D; margin: 4px 0; }

/* ── QTextBrowser (report preview, detail panels) ── */
QTextBrowser {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 6px;
    color: #E6EDF3;
    selection-background-color: #264F78;
}

"""
