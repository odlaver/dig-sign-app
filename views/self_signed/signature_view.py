from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk
from PIL import Image

from self_signed.signature_manager import get_signature_profile, save_signature_image
from views.shared.ui_helpers import button_row, content_card, page_shell, primary_button, secondary_button, set_status, status_label


class SignatureView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        self.selected_path: str | None = None
        self.preview_image = None
        self.preview_label = None
        if self.user is None:
            app.show_login()
            return
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Signature Profile",
            "Profil tanda tangan.",
            self.app.go_back,
        )

        card = content_card(content)

        self.preview_label = ctk.CTkLabel(
            card,
            text="Belum ada tanda tangan.",
            width=420,
            height=180,
            fg_color="#f4f3f6",
            corner_radius=8,
            text_color="#72777e",
        )
        self.preview_label.pack(anchor="w", padx=24, pady=(24, 14))

        existing = get_signature_profile(self.user["id"])
        if existing:
            self.load_preview(existing["signature_image_path"])

        row = button_row(card)
        row.pack_configure(padx=24, pady=(0, 8))
        primary_button(row, "Pilih Gambar", self.choose_file).pack(side="left", padx=(0, 8))
        secondary_button(row, "Simpan", self.save).pack(side="left")

        self.message = status_label(card)
        self.message.pack(fill="x", padx=24, pady=(8, 24))

    def choose_file(self):
        path = filedialog.askopenfilename(
            title="Pilih gambar tanda tangan",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg"),
                ("PNG", "*.png"),
                ("JPEG", "*.jpg *.jpeg"),
            ],
        )
        if not path:
            return
        self.selected_path = path
        self.load_preview(path)
        set_status(self.message, f"File dipilih: {Path(path).name}", None)

    def load_preview(self, path: str):
        image = Image.open(path).convert("RGBA")
        image.thumbnail((340, 140))
        self.preview_image = ctk.CTkImage(light_image=image, dark_image=image, size=image.size)
        self.preview_label.configure(image=self.preview_image, text="")

    def save(self):
        path = self.selected_path
        if not path:
            existing = get_signature_profile(self.user["id"])
            path = existing["signature_image_path"] if existing else None
        if not path:
            set_status(self.message, "Pilih gambar tanda tangan terlebih dahulu.", False)
            return
        try:
            profile = save_signature_image(self.user["id"], path)
        except ValueError as exc:
            set_status(self.message, str(exc), False)
            return
        self.load_preview(profile["signature_image_path"])
        set_status(self.message, "Signature profile berhasil disimpan.", True)
