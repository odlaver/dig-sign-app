from pathlib import Path
from shutil import copyfile
from tkinter import filedialog

import customtkinter as ctk

from ujaja.ca_service import get_ujaja_ca, get_ujaja_digital_id
from views.shared.ui_helpers import button_row, content_card, page_shell, primary_button, set_status, status_label


class CertificateAuthorityView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Certificate Authority",
            "CA internal.",
            self.app.go_back,
        )
        self.ca = get_ujaja_ca()
        self.digital_id = get_ujaja_digital_id()

        card = content_card(content)
        rows = [
            ("Institution", self.ca["institution_name"]),
            ("CA Name", self.ca["ca_name"]),
            ("CA Serial", self.ca["serial_number"]),
            ("CA Status", self.ca["status"]),
            ("Digital ID", self.digital_id["digital_id_name"]),
            ("Digital ID Serial", self.digital_id["serial_number"]),
            ("Digital ID Status", self.digital_id["status"]),
            ("Valid Until", self.ca["expired_at"] or "-"),
        ]
        for label, value in rows:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=24, pady=(16 if label == "Institution" else 4, 4))
            ctk.CTkLabel(row, text=label, width=150, anchor="w", text_color="#72777e").pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="w", text_color="#1a1c1e").pack(side="left")

        self.message = status_label(card)
        self.message.pack(fill="x", padx=24, pady=(14, 4))

        actions = button_row(card)
        actions.pack_configure(padx=24, pady=(8, 24))
        primary_button(actions, "Download CA", self.download_ca, width=150).pack(side="left")

    def download_ca(self):
        source = Path(self.ca["ca_file_path"])
        target = filedialog.asksaveasfilename(
            title="Simpan CA Universitas Jaya Jaya",
            defaultextension=".pem",
            initialfile="universitas_jaya_jaya_root_ca.pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if not target:
            return
        copyfile(source, target)
        set_status(self.message, f"CA berhasil disimpan ke: {target}", True)
