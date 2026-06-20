from pathlib import Path
import re
from PIL import Image
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import AxisAlignment, BoxConstraints, InnerScaling, Margins, SimpleBoxLayoutRule
from pyhanko.sign import signers
from pyhanko.sign import fields
from pyhanko.stamp import StaticStampStyle
from ujaja.ca_service import INSTITUTION_NAME, get_ujaja_ca_certificate_path, get_ujaja_signer_certificate_path, get_ujaja_signer_key_path
SIGNATURE_FIELD_PREFIX = 'UjajaAcrobatSignature'

def _field_fragment(value: str) -> str:
    fragment = re.sub('[^A-Za-z0-9_.-]+', '_', value or '').strip('._')
    return fragment or 'Signature'

def _metadata_dict(pdf_metadata: dict[str, str] | None):
    if not pdf_metadata:
        return None
    info = generic.DictionaryObject()
    for key, value in pdf_metadata.items():
        if value is None:
            continue
        pdf_key = str(key)
        if not pdf_key.startswith('/'):
            pdf_key = f'/{pdf_key}'
        info[generic.pdf_name(pdf_key)] = generic.TextStringObject(str(value))
    return info

def _static_stamp_style(stamp_image: Image.Image, width: int, height: int) -> StaticStampStyle:
    if stamp_image.mode not in ('RGB', 'RGBA'):
        stamp_image = stamp_image.convert('RGBA')
    return StaticStampStyle(border_width=0, background=PdfImage(stamp_image, box=BoxConstraints(width=width, height=height)), background_layout=SimpleBoxLayoutRule(x_align=AxisAlignment.ALIGN_MID, y_align=AxisAlignment.ALIGN_MID, margins=Margins(0, 0, 0, 0), inner_content_scaling=InnerScaling.STRETCH_FILL), background_opacity=1.0)

def apply_acrobat_signature(input_pdf: Path, output_pdf: Path, verification_code: str, key_file: Path=None, cert_file: Path=None, ca_cert_file: Path=None, *, field_name: str=None, field_page: int=0, field_box: tuple[float, float, float, float] | None=None, stamp_image: Image.Image | None=None, pdf_metadata: dict[str, str] | None=None, signer_name: str=INSTITUTION_NAME) -> None:
    if key_file is None:
        key_file = get_ujaja_signer_key_path()
    if cert_file is None:
        cert_file = get_ujaja_signer_certificate_path()
    if ca_cert_file is None:
        ca_cert_file = get_ujaja_ca_certificate_path()
    signer = signers.SimpleSigner.load(key_file=str(key_file), cert_file=str(cert_file), ca_chain_files=(str(ca_cert_file),), key_passphrase=None)
    field_name = field_name or f'{SIGNATURE_FIELD_PREFIX}_{_field_fragment(verification_code)}'
    metadata = signers.PdfSignatureMetadata(field_name=field_name, md_algorithm='sha256', name=signer_name, location='Universitas Jaya Jaya', reason=f'CAP digital signature {verification_code}')
    new_field_spec = None
    stamp_style = None
    if field_box is not None:
        left, bottom, right, top = field_box
        box = (int(round(left)), int(round(bottom)), int(round(right)), int(round(top)))
        new_field_spec = fields.SigFieldSpec(sig_field_name=field_name, on_page=max(0, int(field_page)), box=box, readable_field_name=f'CAP Ujaja Digital Signature {verification_code}')
        if stamp_image is not None:
            stamp_style = _static_stamp_style(stamp_image, max(1, box[2] - box[0]), max(1, box[3] - box[1]))
    with open(input_pdf, 'rb') as source, open(output_pdf, 'wb') as target:
        writer = IncrementalPdfFileWriter(source, strict=False)
        info = _metadata_dict(pdf_metadata)
        if info is not None:
            writer.set_info(info)
        signers.PdfSigner(metadata, signer=signer, stamp_style=stamp_style, new_field_spec=new_field_spec).sign_pdf(writer, output=target)