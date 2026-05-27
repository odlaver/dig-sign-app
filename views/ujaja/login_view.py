import customtkinter as ctk

from ujaja.civitas_service import DEFAULT_CIVITAS, authenticate_civitas, ensure_institution_seed_data
from views.shared.ui_helpers import center_card, field, primary_button, secondary_button, set_status, status_label


class InstitutionLoginView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        ensure_institution_seed_data()
        self.pack_layout()

    def pack_layout(self):
        card = center_card(self, 470)

        ctk.CTkLabel(
            card,
            text="Universitas Jaya Jaya",
            font=ctk.CTkFont(size=25, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", padx=28, pady=(28, 4))
        ctk.CTkLabel(
            card,
            text="Akses civitas.",
            text_color="#42474e",
            wraplength=390,
            justify="left",
        ).pack(anchor="w", padx=28, pady=(0, 12))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=28)
        self.email_entry = field(form, "Email civitas")
        self.password_entry = field(form, "Password", show="*")
        self.email_entry.insert(0, DEFAULT_CIVITAS["email"])
        self.password_entry.insert(0, DEFAULT_CIVITAS["password"])
        self.password_entry.bind("<Return>", lambda _event: self.handle_login())

        self.message = status_label(card)
        self.message.pack(fill="x", padx=28, pady=(12, 6))

        primary_button(card, "Login Civitas", self.handle_login).pack(fill="x", padx=28, pady=(6, 8))
        secondary_button(card, "Verify Academic Signature", self.app.show_institution_verify).pack(
            fill="x",
            padx=28,
            pady=4,
        )
        secondary_button(card, "Kembali ke Mode", self.app.show_mode_selector).pack(
            fill="x",
            padx=28,
            pady=(4, 28),
        )

    def handle_login(self):
        result, error = authenticate_civitas(self.email_entry.get(), self.password_entry.get())
        if error:
            set_status(self.message, error, False)
            return
        self.app.set_current_user(result["user"]["id"])
        self.app.show_institution_dashboard(reset_history=True)
