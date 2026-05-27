from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from core.auth import get_user
from self_signed.digital_id import get_active_digital_id, verify_passphrase
from core.otp_service import verify_code
from self_signed.pdf_signer import create_signed_pdf
from self_signed.signature_manager import get_signature_profile
from views.shared.ui_helpers import button_row, content_card, field, page_shell, primary_button, set_status, status_label


class SignDocumentView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        self.pdf_path: str | None = None
        if self.user is None:
            app.show_login()
            return
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Sign Document",
            "Tanda tangan mandiri.",
            self.app.go_back,
        )

        card = content_card(content)

        self.file_label = ctk.CTkLabel(card, text="Belum ada PDF dipilih.", text_color="#42474e")
        self.file_label.pack(anchor="w", padx=24, pady=(24, 8))
        primary_button(card, "Pilih PDF", self.choose_pdf).pack(anchor="w", padx=24, pady=(0, 12))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=24)
        self.otp_entry = field(form, "Kode OTP")
        self.passphrase_entry = field(form, "Passphrase Digital ID", show="*")
        self.passphrase_entry.bind("<Return>", lambda _event: self.sign())

        self.message = status_label(card)
        self.message.pack(fill="x", padx=24, pady=(12, 4))

        actions = button_row(card)
        actions.pack_configure(padx=24, pady=(8, 24))
        primary_button(actions, "Sign PDF", self.sign).pack(side="left")

    def choose_pdf(self):
        path = filedialog.askopenfilename(
            title="Pilih PDF",
            filetypes=[("PDF files", "*.pdf")],
        )
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
            set_status(self.message, "OTP belum aktif.", False)
            return

        digital_id = get_active_digital_id(fresh_user["id"])
        if digital_id is None:
            set_status(self.message, "Digital ID belum aktif.", False)
            return

        signature = get_signature_profile(fresh_user["id"])
        if signature is None:
            set_status(self.message, "Signature profile belum dibuat.", False)
            return

        if not verify_code(fresh_user["id"], self.otp_entry.get()):
            set_status(self.message, "Kode OTP salah atau kedaluwarsa.", False)
            return

        if not verify_passphrase(fresh_user["id"], self.passphrase_entry.get()):
            set_status(self.message, "Passphrase salah.", False)
            return

        try:
            result = create_signed_pdf(
                fresh_user,
                digital_id,
                self.pdf_path,
                signature["signature_image_path"],
            )
        except ValueError as exc:
            set_status(self.message, str(exc), False)
            return

        set_status(
            self.message,
            "PDF berhasil ditandatangani.\n"
            f"Kode: {result['verification_code']}\n"
            f"Output: {result['output_path']}",
            True,
        )
