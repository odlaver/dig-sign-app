import customtkinter as ctk

from views.shared.ui_helpers import primary_button, secondary_button


class ModeSelectorView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="#f9f9fc")
        self.app = app
        self.pack_layout()

    def pack_layout(self):
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True)
        wrapper.grid_rowconfigure(0, weight=1)
        wrapper.grid_rowconfigure(2, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)

        card = ctk.CTkFrame(wrapper, width=520, fg_color="#ffffff", corner_radius=8)
        card.grid(row=1, column=0, padx=24, pady=24)

        ctk.CTkLabel(
            card,
            text="Ujaja Sign",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", padx=30, pady=(30, 4))
        ctk.CTkLabel(
            card,
            text="Pilih mode.",
            text_color="#42474e",
            font=ctk.CTkFont(size=14),
        ).pack(anchor="w", padx=30, pady=(0, 18))

        personal = ctk.CTkFrame(card, fg_color="#f4f3f6", corner_radius=8)
        personal.pack(fill="x", padx=30, pady=(0, 10))
        ctk.CTkLabel(
            personal,
            text="Self-Signed Digital",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", padx=18, pady=(18, 10))
        secondary_button(personal, "Buka", self.app.start_personal_mode, width=120).pack(
            anchor="w",
            padx=18,
            pady=(0, 18),
        )

        institution = ctk.CTkFrame(card, fg_color="#e8e8eb", corner_radius=8)
        institution.pack(fill="x", padx=30, pady=(0, 30))
        ctk.CTkLabel(
            institution,
            text="Universitas Jaya Jaya",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#1a1c1e",
        ).pack(anchor="w", padx=18, pady=(18, 10))
        primary_button(institution, "Buka", self.app.start_institution_mode, width=120).pack(
            anchor="w",
            padx=18,
            pady=(0, 18),
        )
