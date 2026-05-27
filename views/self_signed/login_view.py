import customtkinter as ctk

from core.auth import DEFAULT_PERSONAL_USER, authenticate
from views.shared.ui_helpers import center_card, field, primary_button, secondary_button, set_status, status_label


class LoginView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app

        card = center_card(self, 430)

        ctk.CTkLabel(
            card,
            text="Self-Signed Digital",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", padx=28, pady=(28, 4))
        ctk.CTkLabel(
            card,
            text="Akses pengguna.",
            text_color="#42474e",
            wraplength=360,
            justify="left",
        ).pack(anchor="w", padx=28, pady=(0, 14))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=28)
        self.email_entry = field(form, "Email")
        self.password_entry = field(form, "Password", show="*")
        self.email_entry.insert(0, DEFAULT_PERSONAL_USER["email"])
        self.password_entry.insert(0, DEFAULT_PERSONAL_USER["password"])
        self.password_entry.bind("<Return>", lambda _event: self.handle_login())

        self.message = status_label(card)
        self.message.pack(fill="x", padx=28, pady=(12, 6))

        primary_button(card, "Login", self.handle_login).pack(fill="x", padx=28, pady=(6, 8))
        secondary_button(card, "Verify Document", app.show_verify_document).pack(fill="x", padx=28, pady=4)
        secondary_button(card, "Kembali ke Mode", app.show_mode_selector).pack(fill="x", padx=28, pady=(4, 28))

    def handle_login(self):
        user = authenticate(self.email_entry.get(), self.password_entry.get())
        if user is None:
            set_status(self.message, "Email atau password salah.", False)
            return
        self.app.set_current_user(user["id"])
        self.app.show_dashboard(reset_history=True)
