"""
Digital Signature panel — Phase 5.

Buttons:  Sign Manifest | Sign Report | Verify Signature
Display:  signer, algorithm, timestamp, artifact SHA-256, and signature
          status (VALID / INVALID / MODIFIED / MISSING / KEY_UNAVAILABLE)
History:  every signature ever recorded for the selected case
          (signatures table, via CaseManager.get_signatures_for_case),
          newest first.

"Sign Manifest" builds + exports the Case Evidence Manifest for the
selected case (reusing manifest_service — no duplicate manifest logic)
and signs that export. "Sign Report" and "Verify Signature" operate on
any file the user picks, so any report already produced by the Reports
panel (HTML/PDF/etc.) can be signed or checked without this panel needing
to know how each report type is generated.
"""

import os
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QFrame, QFileDialog, QGroupBox, QGridLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QSizePolicy,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QBrush

from forensiq.core.case_manager import CaseManager
from forensiq.core.manifest_service import build_manifest, export_manifest_json
from forensiq.core.signature_service import (
    SignatureService, ARTIFACT_MANIFEST, ARTIFACT_REPORT,
    VALID, INVALID, MODIFIED, MISSING, KEY_UNAVAILABLE,
)

_STATUS_COLOR = {
    VALID:           "#3FB950",
    INVALID:         "#F85149",
    MODIFIED:        "#F85149",
    MISSING:         "#E3B341",
    KEY_UNAVAILABLE: "#E3B341",
}


class SignaturePanel(QWidget):
    def __init__(self, db: CaseManager, parent=None):
        super().__init__(parent)
        self.db = db
        self.signer_service = SignatureService(db)
        self._current_case_id: int | None = None
        self._build()

    # ── Build ──────────────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Config card
        cfg = QFrame(); cfg.setObjectName("card")
        cl = QVBoxLayout(cfg)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(10)
        cl.addWidget(self._bold("Signature Configuration"))

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Case:"))
        self.case_combo = QComboBox()
        self.case_combo.setMinimumWidth(340)
        self.case_combo.setPlaceholderText("Select case…")
        self.case_combo.currentIndexChanged.connect(self._on_case_changed)
        r1.addWidget(self.case_combo, 1)
        cl.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Output:"))
        self.out_dir_lbl = QLabel(
            os.path.join(os.path.expanduser("~"), "ForensIQ", "signatures")
        )
        self.out_dir_lbl.setObjectName("metaLabel")
        self.out_dir_lbl.setWordWrap(True)
        browse = QPushButton("Browse…")
        browse.setFixedWidth(80)
        browse.clicked.connect(self._browse_out_dir)
        r2.addWidget(self.out_dir_lbl, 1)
        r2.addWidget(browse)
        cl.addLayout(r2)
        layout.addWidget(cfg)

        # Actions card
        ac = QFrame(); ac.setObjectName("card")
        al = QVBoxLayout(ac)
        al.setContentsMargins(16, 14, 16, 14)
        al.setSpacing(10)
        al.addWidget(self._bold("Actions"))

        row = QHBoxLayout()
        row.setSpacing(8)
        BTN_H = 38
        self.btn_sign_manifest = QPushButton("🖊  Sign Manifest")
        self.btn_sign_manifest.setObjectName("primaryBtn")
        self.btn_sign_manifest.setFixedHeight(BTN_H)
        self.btn_sign_manifest.setToolTip(
            "Build and export the Case Evidence Manifest for the selected "
            "case, then sign it with a detached signature."
        )
        self.btn_sign_manifest.clicked.connect(self._sign_manifest)
        row.addWidget(self.btn_sign_manifest)

        self.btn_sign_report = QPushButton("🖊  Sign Report…")
        self.btn_sign_report.setObjectName("primaryBtn")
        self.btn_sign_report.setFixedHeight(BTN_H)
        self.btn_sign_report.setToolTip(
            "Choose a previously generated report file (HTML/PDF/etc. from "
            "the Reports panel) and sign it with a detached signature."
        )
        self.btn_sign_report.clicked.connect(self._sign_report)
        row.addWidget(self.btn_sign_report)

        self.btn_verify = QPushButton("✔  Verify Signature…")
        self.btn_verify.setFixedHeight(BTN_H)
        self.btn_verify.setToolTip(
            "Choose a signed Manifest or Report file and verify its "
            "detached signature."
        )
        self.btn_verify.clicked.connect(self._verify)
        row.addWidget(self.btn_verify)
        row.addStretch()
        al.addLayout(row)

        self.status_lbl = QLabel("Select a case, then sign or verify an artifact.")
        self.status_lbl.setObjectName("metaLabel")
        self.status_lbl.setWordWrap(True)
        al.addWidget(self.status_lbl)
        layout.addWidget(ac)

        # Result card — signer, algorithm, timestamp, hash, status
        rg = QGroupBox("Signature Result")
        rl = QGridLayout(rg)
        rl.setHorizontalSpacing(18)
        rl.setVerticalSpacing(6)

        self._result_status = self._value_label("—")
        self._result_signer = self._value_label("—")
        self._result_algorithm = self._value_label("—")
        self._result_timestamp = self._value_label("—")
        self._result_artifact_hash = self._value_label("—", mono=True)
        self._result_current_hash = self._value_label("—", mono=True)
        self._result_key_id = self._value_label("—", mono=True)
        self._result_notes = self._value_label("—")
        self._result_notes.setWordWrap(True)

        fields = [
            ("Status:",            self._result_status),
            ("Signer:",            self._result_signer),
            ("Algorithm:",         self._result_algorithm),
            ("Timestamp:",         self._result_timestamp),
            ("Artifact SHA-256:",  self._result_artifact_hash),
            ("Current SHA-256:",   self._result_current_hash),
            ("Key ID:",            self._result_key_id),
            ("Notes:",             self._result_notes),
        ]
        for i, (label, widget) in enumerate(fields):
            lbl = QLabel(label)
            lbl.setObjectName("metaLabel")
            rl.addWidget(lbl, i, 0)
            rl.addWidget(widget, i, 1)
        layout.addWidget(rg)

        # History table
        hg = QGroupBox("Signature History (this case)")
        hl = QVBoxLayout(hg)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Signed At", "Type", "File", "Signer", "Algorithm", "Key ID"]
        )
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hl.addWidget(self.table)
        layout.addWidget(hg, 1)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _bold(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        return l

    def _value_label(self, text: str, mono: bool = False) -> QLabel:
        l = QLabel(text)
        l.setWordWrap(True)
        l.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if mono:
            l.setFont(QFont("Courier New", 10))
        return l

    def _browse_out_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "Output Directory", self.out_dir_lbl.text()
        )
        if path:
            self.out_dir_lbl.setText(path)

    def _current_investigator(self) -> str:
        if not self._current_case_id:
            return ""
        case = self.db.get_case(self._current_case_id)
        return (case["investigator"] if case else "") or ""

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def on_shown(self):
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        for case in self.db.get_all_cases():
            self.case_combo.addItem(
                f"{case['case_number']} — {case['title']}", userData=case["id"]
            )
        self.case_combo.blockSignals(False)
        if self.case_combo.count():
            self._on_case_changed(0)

    def _on_case_changed(self, idx: int):
        cid = self.case_combo.itemData(idx)
        if cid:
            self._current_case_id = cid
            self._refresh_history()

    def _refresh_history(self):
        self.table.setRowCount(0)
        if not self._current_case_id:
            return
        rows = self.db.get_signatures_for_case(self._current_case_id)
        for row in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            values = [
                row["signed_at"], row["artifact_type"],
                os.path.basename(row["artifact_path"]), row["signer"],
                row["algorithm"], row["key_id"],
            ]
            for c, val in enumerate(values):
                self.table.setItem(r, c, QTableWidgetItem(str(val or "")))

    def _show_signed_result(self, meta: dict):
        self._result_status.setText("SIGNED")
        self._result_status.setStyleSheet(f"color:{_STATUS_COLOR.get(VALID)};font-weight:600")
        self._result_signer.setText(meta.get("signer", "—"))
        self._result_algorithm.setText(meta.get("algorithm", "—"))
        self._result_timestamp.setText(meta.get("signed_at", "—"))
        self._result_artifact_hash.setText(meta.get("artifact_sha256", "—"))
        self._result_current_hash.setText(meta.get("artifact_sha256", "—"))
        self._result_key_id.setText(meta.get("key_id", "—"))
        self._result_notes.setText(f"Signature written to {meta.get('signature_path', '—')}")

    def _show_verify_result(self, res: dict):
        status = res.get("status", "—")
        self._result_status.setText(status)
        self._result_status.setStyleSheet(
            f"color:{_STATUS_COLOR.get(status, '#8B949E')};font-weight:600"
        )
        self._result_signer.setText(res.get("signer") or "—")
        self._result_algorithm.setText(res.get("algorithm") or "—")
        self._result_timestamp.setText(res.get("signed_at") or "—")
        self._result_artifact_hash.setText(res.get("artifact_sha256") or "—")
        self._result_current_hash.setText(res.get("current_sha256") or "—")
        self._result_key_id.setText(res.get("key_id") or "—")
        self._result_notes.setText(res.get("notes") or "—")

    # ── Actions ────────────────────────────────────────────────────────────────

    def _sign_manifest(self):
        if not self._current_case_id:
            self.status_lbl.setText("Select a case first.")
            return
        out_dir = self.out_dir_lbl.text().strip()
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError as e:
            self.status_lbl.setText(f"Cannot create output directory: {e}")
            return

        case = self.db.get_case(self._current_case_id)
        cn = case["case_number"] if case else "case"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, f"ForensIQ_{cn}_EvidenceManifest_{ts}.json")

        try:
            manifest = build_manifest(self._current_case_id, self.db)
            export_manifest_json(manifest, path)
            meta = self.signer_service.sign_manifest(
                path, self._current_investigator(), case_id=self._current_case_id
            )
        except Exception as e:
            self.status_lbl.setText(f"Signing failed: {e}")
            QMessageBox.critical(self, "Sign Manifest Failed", str(e))
            return

        self.status_lbl.setText(f"✔ Signed manifest: {path}")
        self._show_signed_result(meta)
        self._refresh_history()
        mw = self.window()
        if hasattr(mw, "audit"):
            mw.audit.log_artifact_signed(
                self._current_case_id, self._current_investigator(),
                ARTIFACT_MANIFEST, path, meta.get("key_id", "")
            )

    def _sign_report(self):
        if not self._current_case_id:
            self.status_lbl.setText("Select a case first.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Report to Sign", self.out_dir_lbl.text(),
            "Reports (*.html *.pdf *.json *.csv);;All Files (*)"
        )
        if not path:
            return
        try:
            meta = self.signer_service.sign_report(
                path, self._current_investigator(), case_id=self._current_case_id
            )
        except Exception as e:
            self.status_lbl.setText(f"Signing failed: {e}")
            QMessageBox.critical(self, "Sign Report Failed", str(e))
            return

        self.status_lbl.setText(f"✔ Signed report: {path}")
        self._show_signed_result(meta)
        self._refresh_history()
        mw = self.window()
        if hasattr(mw, "audit"):
            mw.audit.log_artifact_signed(
                self._current_case_id, self._current_investigator(),
                ARTIFACT_REPORT, path, meta.get("key_id", "")
            )

    def _verify(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Artifact to Verify", self.out_dir_lbl.text(),
            "Artifacts (*.html *.pdf *.json *.csv);;All Files (*)"
        )
        if not path:
            return
        res = self.signer_service.verify_artifact(path, case_id=self._current_case_id)
        self.status_lbl.setText(f"Verification result: {res['status']} — {path}")
        self._show_verify_result(res)

        mw = self.window()
        if hasattr(mw, "audit"):
            mw.audit.log_signature_verified(
                self._current_case_id, self._current_investigator(),
                res.get("artifact_type", ""), path, res["status"]
            )

        if res["status"] != VALID:
            QMessageBox.warning(
                self, "Signature Verification",
                f"Status: {res['status']}\n\n{res.get('notes', '')}"
            )
