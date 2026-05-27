import customtkinter as ctk

from ujaja.civitas_service import get_civitas_for_user
from views.shared.ui_helpers import content_card, page_shell


class CivitasStatusView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.user = app.current_user()
        if self.user is None:
            app.show_institution_login(reset_history=True)
            return
        self.civitas = get_civitas_for_user(self.user["id"])
        if self.civitas is None:
            app.show_institution_login(reset_history=True)
            return
        self.pack_layout()

    def pack_layout(self):
        _shell, content = page_shell(
            self,
            "Civitas Status",
            "Data civitas.",
            self.app.go_back,
        )
        card = content_card(content)
        rows = [
            ("Nama", self.user["name"]),
            ("Civitas ID", self.civitas["employee_id"]),
            ("Email", self.civitas["academic_email"]),
            ("Unit", self.civitas["department"]),
            ("Role", self.civitas["position"]),
            ("Status", self.civitas["employee_status"]),
            ("OTP", "Aktif" if self.user["otp_enabled"] else "Belum aktif"),
        ]
        for label, value in rows:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=24, pady=(16 if label == "Nama" else 4, 4))
            ctk.CTkLabel(row, text=label, width=140, anchor="w", text_color="#72777e").pack(side="left")
            ctk.CTkLabel(
                row,
                text=value,
                anchor="w",
                text_color="#1a1c1e",
                font=ctk.CTkFont(size=14, weight="bold"),
            ).pack(side="left")
