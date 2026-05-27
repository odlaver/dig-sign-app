from pathlib import Path
import os

import customtkinter as ctk

from ujaja.civitas_service import list_institution_sign_requests
from views.shared.ui_helpers import page_shell, primary_button


class InstitutionHistoryView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        if self.user is None:
            app.show_institution_login(reset_history=True)
            return
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Academic Signing History",
            "Riwayat akademik.",
            self.app.go_back,
        )
        list_frame = ctk.CTkScrollableFrame(content, fg_color="#ffffff", corner_radius=8)
        list_frame.pack(fill="both", expand=True)
        list_frame.grid_columnconfigure(0, weight=1)

        documents = list_institution_sign_requests(self.user["id"])
        if not documents:
            ctk.CTkLabel(
                list_frame,
                text="Belum ada dokumen akademik signed.",
                text_color="#72777e",
            ).grid(row=0, column=0, padx=20, pady=20, sticky="w")
            return

        for index, document in enumerate(documents):
            self.document_row(list_frame, index, document)

    def document_row(self, parent, index, document):
        row = ctk.CTkFrame(parent, fg_color="#f4f3f6", corner_radius=8)
        row.grid(row=index, column=0, sticky="ew", padx=12, pady=(12, 0))
        row.grid_columnconfigure(0, weight=1)

        signed_path = Path(document["signed_file_path"])
        title = signed_path.name
        detail = (
            f"Kode: {document['verification_code']} | "
            f"Tanggal: {document['signed_at']} | "
            f"Posisi: {document['signature_position']} | "
            f"Status: {document['status']}"
        )
        ctk.CTkLabel(
            row,
            text=title,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#1a1c1e",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 2))
        ctk.CTkLabel(
            row,
            text=detail,
            text_color="#42474e",
            wraplength=720,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=14, pady=(0, 12))
        primary_button(
            row,
            text="Buka Folder",
            width=110,
            command=lambda path=signed_path: self.open_folder(path),
        ).grid(row=0, column=1, rowspan=2, sticky="e", padx=14, pady=12)

    def open_folder(self, path: Path):
        folder = path.parent
        if folder.exists():
            os.startfile(folder)
