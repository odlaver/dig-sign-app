from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from core.auth import get_user
from ujaja.institution_signer import POSITION_OPTIONS, sign_institution_pdf
from views.shared.ui_helpers import button_row, content_card, field, page_shell, primary_button, set_status, status_label


class InstitutionSignView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        self.pdf_path: str | None = None
        if self.user is None:
            app.show_institution_login(reset_history=True)
            return
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Sign Academic Document",
            "Tanda tangan akademik.",
            self.app.go_back,
        )
        card = content_card(content)
        self.file_label = ctk.CTkLabel(card, text="Belum ada PDF dipilih.", text_color="#42474e")
        self.file_label.pack(anchor="w", padx=24, pady=(24, 8))
        primary_button(card, "Pilih PDF", self.choose_pdf).pack(anchor="w", padx=24, pady=(0, 12))

        ctk.CTkLabel(card, text="Preset posisi tanda tangan", text_color="#42474e").pack(
            anchor="w",
            padx=24,
            pady=(8, 4),
        )
        self.position_menu = ctk.CTkOptionMenu(card, values=list(POSITION_OPTIONS.keys()), width=220, height=40)
        self.position_menu.set("kanan bawah")
        self.position_menu.pack(anchor="w", padx=24)

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=24, pady=(6, 0))
        self.otp_entry = field(form, "Kode OTP")
        self.otp_entry.bind("<Return>", lambda _event: self.sign())

        self.message = status_label(card)
        self.message.pack(fill="x", padx=24, pady=(12, 4))

        actions = button_row(card)
        actions.pack_configure(padx=24, pady=(8, 24))
        primary_button(actions, "Sign with Ujaja Digital ID", self.sign, width=220).pack(side="left")

    def choose_pdf(self):
        path = filedialog.askopenfilename(title="Pilih PDF", filetypes=[("PDF files", "*.pdf")])
        if not path:
            return
        self.pdf_path = path
        self.file_label.configure(text=f"File: {Path(path).name}")
        set_status(self.message, "", None)

    def sign(self):
        fresh_user = get_user(self.user["id"])
        if not self.pdf_path:
            set_status(self.message, "Pilih PDF terlebih dahulu.", False)
            return
        if not fresh_user["otp_enabled"]:
            set_status(self.message, "OTP belum aktif. Buka Setup OTP dulu.", False)
            return

        try:
            result = sign_institution_pdf(
                fresh_user,
                self.pdf_path,
                self.otp_entry.get(),
                self.position_menu.get(),
            )
        except ValueError as exc:
            set_status(self.message, str(exc), False)
            return

        set_status(
            self.message,
            "PDF berhasil ditandatangani dengan Digital ID Universitas Jaya Jaya.\n"
            f"Kode: {result['verification_code']}\n"
            f"Output: {result['output_path']}",
            True,
        )
