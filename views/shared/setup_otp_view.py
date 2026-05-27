import customtkinter as ctk
from PIL import Image

from core import otp_service
from views.shared.ui_helpers import button_row, content_card, page_shell, primary_button, set_status, status_label


class SetupOtpView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        self.qr_image = None
        if self.user is None:
            app.show_login()
            return
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Setup OTP",
            "Autentikasi OTP.",
            self.app.go_back,
        )

        body = content_card(content)

        qr_path = otp_service.generate_qr_code(self.user["id"])
        image = Image.open(qr_path)
        self.qr_image = ctk.CTkImage(light_image=image, dark_image=image, size=(230, 230))
        ctk.CTkLabel(body, image=self.qr_image, text="").pack(anchor="w", padx=24, pady=(24, 8))

        current_status = "OTP sudah aktif." if self.user["otp_enabled"] else "OTP belum aktif."
        ctk.CTkLabel(body, text=current_status, text_color="#42474e").pack(anchor="w", padx=24, pady=(0, 12))

        self.code_entry = ctk.CTkEntry(body, width=260, height=40, placeholder_text="Kode OTP")
        self.code_entry.pack(anchor="w", padx=24)
        self.code_entry.bind("<Return>", lambda _event: self.verify())

        self.message = status_label(body)
        self.message.pack(fill="x", padx=24, pady=(12, 4))

        actions = button_row(body)
        actions.pack_configure(padx=24, pady=(8, 24))
        primary_button(actions, "Verify OTP", self.verify).pack(side="left")

    def verify(self):
        if otp_service.enable_otp(self.user["id"], self.code_entry.get()):
            set_status(self.message, "OTP berhasil diaktifkan.", True)
            self.user = self.app.current_user()
            return
        set_status(self.message, "Kode OTP salah atau sudah kedaluwarsa.", False)
