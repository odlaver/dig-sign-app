import customtkinter as ctk

from self_signed.digital_id import ROLE_OPTIONS, create_or_update_digital_id, get_active_digital_id
from views.shared.ui_helpers import button_row, content_card, field, page_shell, primary_button, set_status, status_label


class DigitalIdRequestView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        if self.user is None:
            app.show_login()
            return
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Digital ID",
            "Identitas digital.",
            self.app.go_back,
        )

        card = content_card(content)

        active = get_active_digital_id(self.user["id"])
        if active:
            ctk.CTkLabel(
                card,
                text=f"Digital ID aktif: {active['serial_number']} ({active['role_title']})",
                text_color="#2F9E44",
                font=ctk.CTkFont(size=15, weight="bold"),
            ).pack(anchor="w", padx=24, pady=(22, 8))

        ctk.CTkLabel(card, text="Role", text_color="#42474e").pack(anchor="w", padx=24, pady=(14, 4))
        self.role_menu = ctk.CTkOptionMenu(card, values=ROLE_OPTIONS, width=260, height=40)
        self.role_menu.pack(anchor="w", padx=24)
        self.role_menu.set(active["role_title"] if active else ROLE_OPTIONS[0])

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=24, pady=(6, 0))
        self.passphrase_entry = field(form, "Passphrase", show="*")
        self.confirm_entry = field(form, "Confirm Passphrase", show="*")
        self.confirm_entry.bind("<Return>", lambda _event: self.create())

        self.message = status_label(card)
        self.message.pack(fill="x", padx=24, pady=(12, 4))

        actions = button_row(card)
        actions.pack_configure(padx=24, pady=(8, 24))
        primary_button(actions, "Aktifkan Digital ID", self.create, width=190).pack(side="left")

    def create(self):
        passphrase = self.passphrase_entry.get()
        if passphrase != self.confirm_entry.get():
            set_status(self.message, "Passphrase dan confirm passphrase harus sama.", False)
            return
        try:
            digital_id = create_or_update_digital_id(
                self.user["id"],
                self.role_menu.get(),
                passphrase,
            )
        except ValueError as exc:
            set_status(self.message, str(exc), False)
            return
        set_status(
            self.message,
            f"Digital ID aktif: {digital_id['serial_number']} ({digital_id['role_title']}).",
            True,
        )
