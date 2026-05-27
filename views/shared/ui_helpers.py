import customtkinter as ctk


BACKGROUND = "#f9f9fc"
SURFACE = "#ffffff"
SURFACE_LOW = "#f4f3f6"
SURFACE_CONTAINER = "#eeedf1"
SURFACE_HIGH = "#e8e8eb"
SURFACE_HIGHEST = "#e2e2e5"
TEXT = "#1a1c1e"
MUTED = "#42474e"
OUTLINE = "#72777e"
OUTLINE_VARIANT = "#c2c7cf"
PRIMARY = "#00243d"
PRIMARY_HOVER = "#0b3a5b"
ON_PRIMARY = "#ffffff"
SECONDARY = "#006876"
SECONDARY_HOVER = "#004e5a"
DANGER = "#ba1a1a"
DANGER_HOVER = "#93000a"
SUCCESS = "#2F9E44"
WARNING = "#F59F00"


def make_page(parent):
    page = ctk.CTkFrame(parent, fg_color=BACKGROUND)
    page.grid_columnconfigure(0, weight=1)
    return page


def page_title(parent, title: str, subtitle: str | None = None):
    ctk.CTkLabel(
        parent,
        text=title,
        font=ctk.CTkFont(size=28, weight="bold"),
        text_color=TEXT,
    ).pack(anchor="w", pady=(0, 4))
    if subtitle:
        ctk.CTkLabel(
            parent,
            text=subtitle,
            font=ctk.CTkFont(size=14),
            text_color=MUTED,
            wraplength=820,
            justify="left",
        ).pack(anchor="w", pady=(0, 20))


def page_shell(parent, title: str, subtitle: str | None = None, back_command=None):
    shell = ctk.CTkFrame(parent, fg_color="transparent")
    shell.pack(fill="both", expand=True, padx=28, pady=24)
    shell.grid_columnconfigure(0, weight=1)
    shell.grid_rowconfigure(1, weight=1)

    header = ctk.CTkFrame(shell, fg_color="transparent")
    header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
    header.grid_columnconfigure(0, weight=1)

    title_box = ctk.CTkFrame(header, fg_color="transparent")
    title_box.grid(row=0, column=0, sticky="ew")
    ctk.CTkLabel(
        title_box,
        text=title,
        font=ctk.CTkFont(size=28, weight="bold"),
        text_color=TEXT,
    ).pack(anchor="w")
    if subtitle:
        ctk.CTkLabel(
            title_box,
            text=subtitle,
            font=ctk.CTkFont(size=14),
            text_color=MUTED,
            wraplength=780,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    content = ctk.CTkFrame(shell, fg_color="transparent")
    content.grid(row=1, column=0, sticky="nsew")
    content.grid_columnconfigure(0, weight=1)
    content.grid_rowconfigure(0, weight=1)

    if back_command is not None:
        footer = ctk.CTkFrame(shell, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", pady=(16, 0))
        secondary_button(footer, "Kembali", back_command, width=110).pack(anchor="w")

    return shell, content


def content_card(parent, fill: str = "x", expand: bool = False):
    card = ctk.CTkFrame(
        parent,
        fg_color=SURFACE,
        corner_radius=8,
        border_width=1,
        border_color=OUTLINE_VARIANT,
    )
    card.pack(fill=fill, expand=expand)
    return card


def status_label(parent):
    return ctk.CTkLabel(
        parent,
        text="",
        font=ctk.CTkFont(size=13),
        text_color=MUTED,
        wraplength=720,
        justify="left",
    )


def set_status(label, message: str, ok: bool | None = None):
    color = MUTED
    if ok is True:
        color = SUCCESS
    elif ok is False:
        color = DANGER
    label.configure(text=message, text_color=color)


def field(parent, label: str, show: str | None = None):
    ctk.CTkLabel(parent, text=label, text_color=MUTED).pack(anchor="w", pady=(8, 4))
    entry = ctk.CTkEntry(
        parent,
        height=40,
        show=show,
        border_width=1,
        border_color=OUTLINE_VARIANT,
        fg_color=SURFACE,
        text_color=TEXT,
    )
    entry.pack(fill="x")
    return entry


def primary_button(parent, text: str, command, width: int = 150):
    return ctk.CTkButton(
        parent,
        text=text,
        width=width,
        height=40,
        command=command,
        corner_radius=6,
        fg_color=PRIMARY,
        hover_color=PRIMARY_HOVER,
        text_color=ON_PRIMARY,
    )


def secondary_button(parent, text: str, command, width: int = 150):
    return ctk.CTkButton(
        parent,
        text=text,
        width=width,
        height=38,
        command=command,
        corner_radius=6,
        fg_color=SURFACE_CONTAINER,
        hover_color=SURFACE_HIGH,
        text_color=TEXT,
        border_width=1,
        border_color=OUTLINE_VARIANT,
    )


def danger_button(parent, text: str, command, width: int = 120):
    return ctk.CTkButton(
        parent,
        text=text,
        width=width,
        height=38,
        command=command,
        corner_radius=6,
        fg_color=DANGER,
        hover_color=DANGER_HOVER,
        text_color=ON_PRIMARY,
    )


def center_card(parent, width: int = 430):
    wrapper = ctk.CTkFrame(parent, fg_color="transparent")
    wrapper.pack(fill="both", expand=True)
    wrapper.grid_rowconfigure(0, weight=1)
    wrapper.grid_rowconfigure(2, weight=1)
    wrapper.grid_columnconfigure(0, weight=1)

    card = ctk.CTkFrame(
        wrapper,
        width=width,
        corner_radius=8,
        fg_color=SURFACE,
        border_width=1,
        border_color=OUTLINE_VARIANT,
    )
    card.grid(row=1, column=0, padx=24, pady=24)
    return card


def button_row(parent):
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(anchor="w", fill="x")
    return row
