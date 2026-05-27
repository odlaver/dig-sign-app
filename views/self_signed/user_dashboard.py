import customtkinter as ctk

from core.auth import count_signed_documents
from self_signed.digital_id import get_active_digital_id
from self_signed.signature_manager import get_signature_profile
from views.shared.ui_helpers import danger_button, primary_button


class UserDashboard(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        if self.user is None:
            app.show_login()
            return

        self.pack_layout()

    def pack_layout(self):
        shell = ctk.CTkFrame(self, fg_color="transparent")
        shell.pack(fill="both", expand=True, padx=28, pady=24)
        shell.grid_columnconfigure(0, weight=1)
        shell.grid_rowconfigure(2, weight=1)

        top = ctk.CTkFrame(shell, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        title_box = ctk.CTkFrame(top, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            title_box,
            text="Self-Signed Digital",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(
            title_box,
            text=self.user["name"],
            font=ctk.CTkFont(size=14),
            text_color="#42474e",
            wraplength=760,
            justify="left",
        ).pack(anchor="w", pady=(0, 18))
        danger_button(
            top,
            text="Logout",
            width=100,
            command=self.app.logout,
        ).grid(row=0, column=1, sticky="ne")

        status_grid = ctk.CTkFrame(shell, fg_color="transparent")
        status_grid.grid(row=1, column=0, sticky="ew", pady=(4, 20))
        for col in range(4):
            status_grid.grid_columnconfigure(col, weight=1)

        digital_id = get_active_digital_id(self.user["id"])
        signature = get_signature_profile(self.user["id"])
        signed_count = count_signed_documents(self.user["id"])
        self.status_card(status_grid, 0, "OTP", "Aktif" if self.user["otp_enabled"] else "Belum aktif")
        self.status_card(status_grid, 1, "Digital ID", digital_id["role_title"] if digital_id else "Belum dibuat")
        self.status_card(status_grid, 2, "Signature", "Tersimpan" if signature else "Belum ada")
        self.status_card(status_grid, 3, "Signed Docs", str(signed_count))

        menu = ctk.CTkFrame(shell, fg_color="#ffffff", corner_radius=8)
        menu.grid(row=2, column=0, sticky="nsew")
        menu.grid_columnconfigure((0, 1, 2), weight=1)
        menu.grid_rowconfigure((0, 1), weight=1)

        actions = [
            ("Setup OTP", "", self.app.show_setup_otp),
            ("Digital ID", "", self.app.show_digital_id),
            ("Signature Profile", "", self.app.show_signature),
            ("Sign Document", "", self.app.show_sign_document),
            ("Verify Document", "", self.app.show_verify_document),
            ("History", "", self.app.show_history),
        ]
        for index, (title, desc, command) in enumerate(actions):
            self.action_card(menu, index, title, desc, command)

    def status_card(self, parent, col, label, value):
        card = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=8)
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 8, 0), pady=0)
        ctk.CTkLabel(card, text=label, text_color="#72777e").pack(anchor="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", padx=16, pady=(0, 14))

    def action_card(self, parent, index, title, desc, command):
        row = index // 3
        col = index % 3
        card = ctk.CTkFrame(parent, fg_color="#f4f3f6", corner_radius=8)
        card.grid(row=row, column=col, sticky="nsew", padx=12, pady=12)
        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", padx=18, pady=(18, 4))
        if desc:
            ctk.CTkLabel(
                card,
                text=desc,
                text_color="#42474e",
                wraplength=260,
                justify="left",
            ).pack(anchor="w", padx=18, pady=(0, 14))
            button_pady = (0, 18)
        else:
            button_pady = (8, 18)
        primary_button(card, "Buka", command, width=110).pack(anchor="w", padx=18, pady=button_pady)
