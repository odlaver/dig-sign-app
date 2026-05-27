import customtkinter as ctk

from core.auth import ensure_default_personal_user, get_user
from ujaja.civitas_service import ensure_institution_seed_data
from core.database import init_db
from views.ujaja.ca_view import CertificateAuthorityView
from views.ujaja.civitas_status_view import CivitasStatusView
from views.self_signed.digital_id_request_view import DigitalIdRequestView
from views.self_signed.history_view import HistoryView
from views.ujaja.dashboard_view import InstitutionDashboard
from views.ujaja.history_view import InstitutionHistoryView
from views.ujaja.login_view import InstitutionLoginView
from views.ujaja.sign_view import InstitutionSignView
from views.ujaja.verify_view import InstitutionVerifyView
from views.self_signed.login_view import LoginView
from views.shared.mode_selector_view import ModeSelectorView
from views.shared.setup_otp_view import SetupOtpView
from views.self_signed.sign_document_view import SignDocumentView
from views.self_signed.signature_view import SignatureView
from views.self_signed.user_dashboard import UserDashboard
from views.self_signed.verify_document_view import VerifyDocumentView


class UjajaSignApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        init_db()
        ensure_default_personal_user()
        ensure_institution_seed_data()

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.title("Ujaja Sign - Universitas Jaya Jaya")
        self.geometry("1040x720")
        self.minsize(900, 620)

        self.current_user_id: int | None = None
        self.current_mode: str | None = None
        self.navigation_stack: list[tuple[type[ctk.CTkFrame], dict]] = []
        self.current_frame_class: type[ctk.CTkFrame] | None = None
        self.current_frame_kwargs: dict = {}
        self.container = ctk.CTkFrame(self, fg_color="#f9f9fc")
        self.container.pack(fill="both", expand=True)

        self.show_mode_selector()

    def current_user(self):
        if self.current_user_id is None:
            return None
        return get_user(self.current_user_id)

    def set_current_user(self, user_id: int | None) -> None:
        self.current_user_id = user_id

    def show_frame(
        self,
        frame_class,
        push_history: bool = True,
        clear_history: bool = False,
        **kwargs,
    ) -> None:
        if clear_history:
            self.navigation_stack.clear()
        elif push_history and self.current_frame_class is not None:
            self.navigation_stack.append(
                (self.current_frame_class, dict(self.current_frame_kwargs))
            )

        for child in self.container.winfo_children():
            child.destroy()

        self.current_frame_class = frame_class
        self.current_frame_kwargs = dict(kwargs)
        frame = frame_class(self.container, self, **kwargs)
        frame.pack(fill="both", expand=True)

    def go_back(self) -> None:
        if self.navigation_stack:
            frame_class, kwargs = self.navigation_stack.pop()
            self.show_frame(frame_class, push_history=False, **kwargs)
            return

        if self.current_user_id is not None:
            if self.current_mode == "institution":
                self.show_institution_dashboard(reset_history=True)
            else:
                self.show_dashboard(reset_history=True)
        else:
            self.show_mode_selector()

    def logout(self) -> None:
        self.show_mode_selector()

    def show_mode_selector(self) -> None:
        self.set_current_user(None)
        self.current_mode = None
        self.show_frame(ModeSelectorView, push_history=False, clear_history=True)

    def start_personal_mode(self) -> None:
        self.current_mode = "personal"
        self.show_login(reset_history=True)

    def start_institution_mode(self) -> None:
        self.current_mode = "institution"
        self.show_institution_login(reset_history=True)

    def show_login(self, reset_history: bool = True) -> None:
        self.set_current_user(None)
        self.current_mode = "personal"
        self.show_frame(LoginView, push_history=False, clear_history=reset_history)

    def show_dashboard(self, reset_history: bool = False) -> None:
        self.current_mode = "personal"
        self.show_frame(
            UserDashboard,
            push_history=not reset_history,
            clear_history=reset_history,
        )

    def show_setup_otp(self) -> None:
        self.show_frame(SetupOtpView)

    def show_digital_id(self) -> None:
        self.show_frame(DigitalIdRequestView)

    def show_signature(self) -> None:
        self.show_frame(SignatureView)

    def show_sign_document(self) -> None:
        self.show_frame(SignDocumentView)

    def show_verify_document(self) -> None:
        self.show_frame(VerifyDocumentView)

    def show_history(self) -> None:
        self.show_frame(HistoryView)

    def show_institution_login(self, reset_history: bool = False) -> None:
        self.set_current_user(None)
        self.current_mode = "institution"
        self.show_frame(
            InstitutionLoginView,
            push_history=not reset_history,
            clear_history=reset_history,
        )

    def show_institution_dashboard(self, reset_history: bool = False) -> None:
        self.current_mode = "institution"
        self.show_frame(
            InstitutionDashboard,
            push_history=not reset_history,
            clear_history=reset_history,
        )

    def show_civitas_status(self) -> None:
        self.show_frame(CivitasStatusView)

    def show_certificate_authority(self) -> None:
        self.show_frame(CertificateAuthorityView)

    def show_institution_sign(self) -> None:
        self.show_frame(InstitutionSignView)

    def show_institution_verify(self) -> None:
        self.show_frame(InstitutionVerifyView)

    def show_institution_history(self) -> None:
        self.show_frame(InstitutionHistoryView)


if __name__ == "__main__":
    app = UjajaSignApp()
    app.mainloop()
