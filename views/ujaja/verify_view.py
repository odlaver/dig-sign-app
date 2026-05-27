from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from ujaja.institution_signer import verify_institution_pdf
from views.shared.ui_helpers import button_row, content_card, page_shell, primary_button


class InstitutionVerifyView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.pdf_path: str | None = None
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Verify Academic Signature",
            "Verifikasi akademik.",
            self.app.go_back,
        )
        card = content_card(content, fill="both", expand=True)
        self.file_label = ctk.CTkLabel(card, text="Belum ada PDF dipilih.", text_color="#42474e")
        self.file_label.pack(anchor="w", padx=24, pady=(24, 8))

        actions = button_row(card)
        actions.pack_configure(padx=24, pady=(0, 14))
        primary_button(actions, "Pilih PDF", self.choose_pdf).pack(side="left", padx=(0, 8))
        primary_button(actions, "Verify", self.verify, width=120).pack(side="left")

        self.result_box = ctk.CTkTextbox(card, height=280, wrap="word")
        self.result_box.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        self.write_result("Belum diverifikasi.")

    def choose_pdf(self):
        path = filedialog.askopenfilename(title="Pilih PDF", filetypes=[("PDF files", "*.pdf")])
        if not path:
            return
        self.pdf_path = path
        self.file_label.configure(text=f"File: {Path(path).name}")

    def write_result(self, text: str):
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", text)
        self.result_box.configure(state="disabled")

    def verify(self):
        if not self.pdf_path:
            self.write_result("Pilih PDF terlebih dahulu.")
            return

        result = verify_institution_pdf(self.pdf_path)
        if result.get("valid"):
            text = (
                "Status: Valid\n"
                f"Ditandatangani oleh: {result['employee_name']} ({result['employee_email']})\n"
                f"Civitas ID: {result['employee_id']}\n"
                f"Role: {result['position']}\n"
                f"Issuer: {result['institution_name']}\n"
                f"Unit: {result['department']}\n"
                f"Waktu tanda tangan: {result['signed_at']}\n"
                f"CA: Valid - {result['ca_serial']}\n"
                f"Digital ID Institusi: Aktif - {result['digital_id_serial']}\n"
                "Hash: Cocok\n"
                "Signature Value: Valid"
            )
        else:
            text = (
                "Status: Tidak Valid\n"
                f"Alasan: {result.get('reason')}\n"
                f"Kode: {result.get('code') or '-'}"
            )
            if "hash_match" in result:
                text += (
                    f"\nHash cocok: {'Ya' if result.get('hash_match') else 'Tidak'}"
                    f"\nCA cocok: {'Ya' if result.get('ca_match') else 'Tidak'}"
                    f"\nDigital ID cocok: {'Ya' if result.get('digital_id_match') else 'Tidak'}"
                    f"\nSignature Value valid: {'Ya' if result.get('signature_valid') else 'Tidak'}"
                )
        self.write_result(text)
