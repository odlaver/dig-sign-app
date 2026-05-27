from pathlib import Path

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers

from ujaja.ca_service import (
    INSTITUTION_NAME,
    get_ujaja_ca_certificate_path,
    get_ujaja_signer_certificate_path,
    get_ujaja_signer_key_path,
)


SIGNATURE_FIELD_NAME = "UjajaAcrobatSignature"


def apply_acrobat_signature(input_pdf: Path, output_pdf: Path, verification_code: str) -> None:
    signer = signers.SimpleSigner.load(
        key_file=str(get_ujaja_signer_key_path()),
        cert_file=str(get_ujaja_signer_certificate_path()),
        ca_chain_files=(str(get_ujaja_ca_certificate_path()),),
        key_passphrase=None,
    )
    metadata = signers.PdfSignatureMetadata(
        field_name=SIGNATURE_FIELD_NAME,
        md_algorithm="sha256",
        name=INSTITUTION_NAME,
        location="Universitas Jaya Jaya",
        reason=f"Academic document approval {verification_code}",
    )

    with open(input_pdf, "rb") as source, open(output_pdf, "wb") as target:
        writer = IncrementalPdfFileWriter(source, strict=False)
        signers.PdfSigner(metadata, signer=signer).sign_pdf(writer, output=target)
