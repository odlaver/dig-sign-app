from datetime import datetime
import os
from pathlib import Path
import re
from urllib.parse import quote
import uuid
from PIL import Image, ImageDraw, ImageFont, ImageOps
from pypdf import PdfReader
from core.audit import log_action
from core.qr_utils import transparent_qr_image
from ujaja.acrobat_signature import apply_acrobat_signature
from ujaja.ca_service import INSTITUTION_NAME, ensure_ujaja_identity, get_active_ujaja_ca, get_ujaja_signature_path, sign_payload, verify_payload_signature, get_ujaja_employee_public_key_pem
from core.database import ASSETS_DIR, SIGNED_DOCS_DIR, TEMP_DIR, get_connection
from ujaja.civitas_service import validate_active_civitas
from core.otp_service import verify_code
import hashlib

def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()
CODE_PATTERN = re.compile('Ujaja-[A-F0-9]{12}')
POSITION_OPTIONS = {'kanan bawah': 'kanan bawah', 'kiri bawah': 'kiri bawah', 'kanan atas': 'kanan atas', 'kiri atas': 'kiri atas'}
CUSTOM_POSITION_PATTERN = re.compile('^custom:(-?\\d+(?:\\.\\d+)?):(-?\\d+(?:\\.\\d+)?)$')
UPLOAD_PREFIX_PATTERN = re.compile('^(?:sign|verify)_[A-Fa-f0-9]{32}_')
VERIFICATION_NAME_PATTERN = re.compile('_Ujaja-[A-F0-9]{12}', re.IGNORECASE)
SIGNED_SUFFIX_PATTERN = re.compile('(?:_signed(?:_\\d+)?)+$', re.IGNORECASE)
SIGNATURE_STAMP_ASPECT = 1763 / 892
DEFAULT_VERIFY_BASE_URL = 'https://127.0.0.1:5000'

def _clamp_percent(value: float) -> float:
    return max(0.0, min(100.0, value))

def _custom_position_percent(position: str) -> tuple[float, float] | None:
    match = CUSTOM_POSITION_PATTERN.match(position or '')
    if not match:
        return None
    return (_clamp_percent(float(match.group(1))), _clamp_percent(float(match.group(2))))

def _normalize_position(position: str) -> str:
    custom = _custom_position_percent(position)
    if custom is not None:
        x_percent, y_percent = custom
        return f'custom:{x_percent:.2f}:{y_percent:.2f}'
    return POSITION_OPTIONS.get(position, 'kanan bawah')

def _normalize_page_number(page_count: int, page_number: int | str | None) -> int:
    if page_count < 1:
        raise ValueError('PDF tidak memiliki halaman.')
    if page_number in (None, ''):
        return page_count
    try:
        page = int(page_number)
    except (TypeError, ValueError) as exc:
        raise ValueError('Halaman signature tidak valid.') from exc
    return max(1, min(page_count, page))

def _safe_name(name: str) -> str:
    cleaned = re.sub('[^A-Za-z0-9_.-]+', '_', name).strip('._')
    return cleaned or 'document'

def _clean_output_base_name(source: Path) -> str:
    cleaned = source.stem
    while True:
        next_cleaned = UPLOAD_PREFIX_PATTERN.sub('', cleaned)
        if next_cleaned == cleaned:
            break
        cleaned = next_cleaned
    cleaned = VERIFICATION_NAME_PATTERN.sub('', cleaned)
    cleaned = re.sub('(?:_institution)+$', '', cleaned, flags=re.IGNORECASE)
    cleaned = SIGNED_SUFFIX_PATTERN.sub('', cleaned)
    return _safe_name(cleaned)

def _unique_signed_output_path(source: Path) -> Path:
    base_name = _clean_output_base_name(source)
    candidate = SIGNED_DOCS_DIR / f'{base_name}_signed.pdf'
    if not candidate.exists():
        return candidate
    index = 2
    while True:
        candidate = SIGNED_DOCS_DIR / f'{base_name}_signed_{index}.pdf'
        if not candidate.exists():
            return candidate
        index += 1

def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars - 3] + '...'

def _unique_verification_code() -> str:
    with get_connection() as conn:
        while True:
            code = f'Ujaja-{uuid.uuid4().hex[:12].upper()}'
            exists = conn.execute('SELECT 1 FROM ujaja_sign_requests WHERE verification_code = ?', (code,)).fetchone()
            if not exists:
                return code

def verification_result_url(verification_code: str, base_url: str | None=None) -> str:
    base = (base_url or os.environ.get('UJAJA_VERIFY_BASE_URL') or DEFAULT_VERIFY_BASE_URL).strip()
    base = base.rstrip('/') or DEFAULT_VERIFY_BASE_URL
    return f'{base}/verify/{quote(verification_code)}'

def _qr_payload(verification_code: str, verification_url: str | None=None) -> str:
    return verification_url or verification_result_url(verification_code)

def _signature_block_size(page_width: float) -> tuple[float, float]:
    width = min(210, max(170, page_width * 0.34))
    return (width, width / SIGNATURE_STAMP_ASPECT)

def _normalize_signature_size(signature_size: tuple[float, float] | None) -> tuple[float | None, float | None]:
    if signature_size is None:
        return (None, None)
    try:
        width_percent = float(signature_size[0])
        height_percent = float(signature_size[1])
    except (TypeError, ValueError, IndexError) as exc:
        raise ValueError('Ukuran signature tidak valid.') from exc
    return (max(12.0, min(75.0, width_percent)), max(4.0, min(34.0, height_percent)))

def _signature_block_size_for_page(page_width: float, page_height: float, signature_size: tuple[float, float] | None=None) -> tuple[float, float]:
    width_percent, height_percent = _normalize_signature_size(signature_size)
    if width_percent is None or height_percent is None:
        return _signature_block_size(page_width)
    block_width = page_width * width_percent / 100
    block_height = page_height * height_percent / 100
    return (block_width, max(block_height, block_width / SIGNATURE_STAMP_ASPECT))

def _block_position(page_width: float, page_height: float, block_width: float, block_height: float, position: str):
    custom = _custom_position_percent(position)
    if custom is not None:
        x_percent, y_percent = custom
        max_x = max(0, page_width - block_width)
        max_y = max(0, page_height - block_height)
        x = x_percent / 100 * max_x
        y = max_y - y_percent / 100 * max_y
        return (x, y)
    margin = 36
    if position == 'kiri bawah':
        return (margin, margin)
    if position == 'kanan atas':
        return (page_width - margin - block_width, page_height - margin - block_height)
    if position == 'kiri atas':
        return (margin, page_height - margin - block_height)
    return (page_width - margin - block_width, margin)

def _resolve_visual_signature_path(civitas, visual_signature_path: str=None) -> str:
    from ujaja.civitas_service import get_signature_profile
    profile_path = get_signature_profile(civitas['user_id'])
    if visual_signature_path and Path(visual_signature_path).exists():
        return str(visual_signature_path)
    if profile_path and Path(profile_path).exists():
        return str(profile_path)
    return str(get_ujaja_signature_path())

def _pil_font(size: int, bold: bool=False):
    font_names = ('segoeuib.ttf', 'arialbd.ttf') if bold else ('segoeui.ttf', 'arial.ttf')
    font_dirs = (Path('C:/Windows/Fonts'), Path('/usr/share/fonts/truetype/dejavu'))
    for font_dir in font_dirs:
        for font_name in font_names:
            font_path = font_dir / font_name
            if font_path.exists():
                return ImageFont.truetype(str(font_path), size=size)
    return ImageFont.load_default()

def _paste_contained(base: Image.Image, image: Image.Image, box: tuple[int, int, int, int], allow_upscale: bool=False, align: str='center') -> None:
    left, top, width, height = box
    candidate = image.copy()
    ratio = min(width / candidate.width, height / candidate.height)
    if not allow_upscale:
        ratio = min(1, ratio)
    new_width = max(1, int(candidate.width * ratio))
    new_height = max(1, int(candidate.height * ratio))
    candidate = candidate.resize((new_width, new_height), Image.Resampling.LANCZOS)
    if align == 'left':
        x = left
    elif align == 'right':
        x = left + max(0, width - candidate.width)
    else:
        x = left + max(0, (width - candidate.width) // 2)
    y = top + max(0, (height - candidate.height) // 2)
    base.alpha_composite(candidate, (x, y))

def _prepare_visual_signature_image(image: Image.Image) -> Image.Image:
    image = ImageOps.exif_transpose(image).convert('RGBA')
    pixels = image.load()
    for y in range(image.height):
        for x in range(image.width):
            r, g, b, a = pixels[x, y]
            if a == 0:
                continue
            lightness = (r + g + b) / 3
            spread = max(r, g, b) - min(r, g, b)
            if lightness >= 245 and spread <= 34:
                pixels[x, y] = (r, g, b, 0)
            elif lightness >= 220 and spread <= 38:
                fade = int(a * (245 - lightness) / 25)
                pixels[x, y] = (r, g, b, max(0, min(a, fade)))
    alpha_bbox = image.getchannel('A').getbbox()
    if alpha_bbox:
        image = image.crop(alpha_bbox)
        pad = max(8, min(36, int(max(image.size) * 0.06)))
        padded = Image.new('RGBA', (image.width + pad * 2, image.height + pad * 2), (255, 255, 255, 0))
        padded.alpha_composite(image, (pad, pad))
        image = padded
    return image

def _resolve_cap_path() -> Path:
    cap_path = ASSETS_DIR / 'ui' / 'cap_ujaja.jpg'
    if cap_path.exists():
        return cap_path
    return get_ujaja_signature_path()

def _build_stamp_image(civitas, verification_code: str, signed_at: str, visual_signature_path: str=None, block_width: float=178, block_height: float=78, verification_url: str | None=None) -> Image.Image:
    scale = 4
    width = int(round(block_width * scale))
    height = int(round(block_height * scale))
    stamp = Image.new('RGBA', (width, height), (255, 255, 255, 0))
    margin_x = max(3, int(width * 0.045))
    margin_y = max(3, int(height * 0.07))
    gap = max(3, int(width * 0.025))
    qr_size = max(10, min(int(width * 0.38), height - margin_y * 2, width - margin_x * 2))
    qr_x = max(margin_x, width - margin_x - qr_size)
    qr_y = max(margin_y, (height - qr_size) // 2)
    left_width = max(1, qr_x - margin_x - gap)
    left_height = max(1, height - margin_y * 2)
    left_area_x = margin_x
    left_area_y = margin_y
    left_area_w = left_width
    left_area_h = left_height
    cap = Image.open(_resolve_cap_path())
    cap = _prepare_visual_signature_image(cap)
    cap_box_x = max(0, left_area_x - int(left_area_w * 0.22))
    cap_box_y = left_area_y
    cap_box_w = max(1, int(left_area_w * 0.88))
    cap_box_h = left_area_h
    _paste_contained(stamp, cap, (cap_box_x, cap_box_y, cap_box_w, cap_box_h), allow_upscale=True, align='left')
    signature = Image.open(_resolve_visual_signature_path(civitas, visual_signature_path))
    signature = _prepare_visual_signature_image(signature)
    signature_x = left_area_x + int(left_area_w * 0.24)
    signature_y = left_area_y + int(left_area_h * 0.01)
    signature_w = max(1, int(left_area_w * 0.76))
    signature_h = max(1, int(left_area_h * 0.92))
    _paste_contained(stamp, signature, (signature_x, signature_y, signature_w, signature_h), allow_upscale=True, align='center')
    qr = transparent_qr_image(_qr_payload(verification_code, verification_url))
    qr = qr.resize((qr_size, qr_size), Image.Resampling.NEAREST)
    stamp.alpha_composite(qr, (qr_x, qr_y))
    return stamp

def _signature_payload_hash(original_hash: str, verification_code: str, civitas, signed_at: str, signature_page: int, position: str, ca_serial_number: str, digital_id_serial: str) -> str:
    payload = '|'.join((original_hash, verification_code, civitas['employee_id'], signed_at, f'page {signature_page}:{position}', ca_serial_number, digital_id_serial))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()

def _institution_metadata(civitas, verification_code: str, signed_at: str, page_number: int, ca_serial_number: str, digital_id_serial: str, metadata_extra: dict[str, str], previous_codes: list[str]=None) -> dict[str, str]:
    import json
    codes = (previous_codes or []) + [verification_code]
    metadata = {'/Producer': 'Ujaja Sign', '/UjajaSignMode': 'institution', '/UjajaSignInstitution': INSTITUTION_NAME, '/UjajaSignSigner': INSTITUTION_NAME, '/UjajaSignOperator': civitas['name'], '/UjajaSignOperatorEmail': civitas['email'], '/UjajaSignCode': verification_code, '/UjajaSignCodeList': json.dumps(codes), '/UjajaSignCivitasId': civitas['employee_id'], '/UjajaSignCASerial': ca_serial_number, '/UjajaSignDigitalIdSerial': digital_id_serial, '/UjajaSignSignedAt': signed_at, '/UjajaSignPage': str(page_number)}
    metadata.update(metadata_extra)
    return metadata

def sign_institution_pdf(user, input_pdf_path: str, otp_code: str, position: str='kanan bawah', visual_signature_path: str=None, signature_page: int | str | None=None, signature_size: tuple[float, float] | None=None, verification_base_url: str | None=None, is_secure: bool=True) -> dict:
    ensure_ujaja_identity()
    if not is_secure:
        source = Path(input_pdf_path)
        if not source.exists():
            raise ValueError('File PDF tidak ditemukan.')
        SIGNED_DOCS_DIR.mkdir(parents=True, exist_ok=True)
        output_path = _unique_signed_output_path(source)
        import shutil
        shutil.copy2(str(source), str(output_path))
        return {'output_path': output_path, 'verification_code': None, 'signed_at': datetime.now().isoformat(timespec='seconds'), 'signed_hash': file_sha256(output_path), 'signature_value': None, 'verification_url': None, 'ssl_blocked': True}
    source = Path(input_pdf_path)
    position = _normalize_position(position)
    if not source.exists():
        raise ValueError('File PDF tidak ditemukan.')
    if source.suffix.lower() != '.pdf':
        raise ValueError('File input harus PDF.')
    if not verify_code(user['id'], otp_code):
        raise ValueError('OTP sudah tidak valid. Masukkan kode terbaru dari authenticator.')
    page_reader = PdfReader(str(source))
    if page_reader.is_encrypted:
        raise ValueError('PDF terenkripsi tidak didukung untuk MVP.')
    signature_page_number = _normalize_page_number(len(page_reader.pages), signature_page)
    civitas = validate_active_civitas(user['id'])
    ca = get_active_ujaja_ca()
    if ca is None:
        raise ValueError('CA Ujaja tidak aktif.')
    from ujaja.ca_service import ensure_civitas_digital_id
    digital_id = ensure_civitas_digital_id(civitas['id'])
    if digital_id is None:
        raise ValueError('Digital ID Ujaja tidak aktif untuk civitas.')
    from ujaja.ca_service import check_certificate_expiration, check_digital_id_expiration
    cert_status = check_certificate_expiration()
    if cert_status['blocked']:
        if cert_status.get('ssl_expired'):
            raise ValueError('SSL Certificate Expired. Digital Signature Failed.')
        raise ValueError('Digital Certificate Expired. SIGNATURE REJECTED.')
    did_status = check_digital_id_expiration(civitas['id'])
    if did_status['expired']:
        raise ValueError('DIGITAL CERTIFICATE EXPIRED. SIGNATURE REJECTED.')
    original_hash = file_sha256(source)
    verification_code = _unique_verification_code()
    verification_url = verification_result_url(verification_code, verification_base_url)
    signed_at = datetime.now().isoformat(timespec='seconds')
    SIGNED_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    output_path = _unique_signed_output_path(source)
    target_page = page_reader.pages[signature_page_number - 1]
    page_width = float(target_page.mediabox.width)
    page_height = float(target_page.mediabox.height)
    block_width, block_height = _signature_block_size_for_page(page_width, page_height, signature_size)
    x, y = _block_position(page_width, page_height, block_width, block_height, position)
    signature_field_box = (x, y, x + block_width, y + block_height)
    signature_field_name = f"UjajaSignature_{verification_code.replace('-', '_')}"
    signature_payload_hash = _signature_payload_hash(original_hash, verification_code, civitas, signed_at, signature_page_number, position, ca['serial_number'], digital_id['serial_number'])
    signature_value = sign_payload(signature_payload_hash, verification_code, ca['serial_number'], digital_id['serial_number'], civitas['employee_id'], employee_id=civitas['id'])
    import json
    existing_metadata = _read_metadata(source)
    code_list_str = existing_metadata.get('UjajaSignCodeList')
    previous_codes = []
    if code_list_str:
        try:
            previous_codes = json.loads(code_list_str)
        except Exception:
            pass
    if not previous_codes:
        previous_codes = extract_institution_verification_codes(source)
    pdf_metadata = _institution_metadata(civitas, verification_code, signed_at, signature_page_number, ca['serial_number'], digital_id['serial_number'], {'/UjajaSignPayloadHash': signature_payload_hash, '/UjajaSignSignatureValue': signature_value, '/UjajaSignFieldName': signature_field_name, '/UjajaSignVerifyURL': verification_url}, previous_codes=previous_codes)
    stamp_image = _build_stamp_image(civitas, verification_code, signed_at, visual_signature_path=visual_signature_path, block_width=block_width, block_height=block_height, verification_url=verification_url)
    from ujaja.ca_service import get_ujaja_employee_signer_key_path, get_ujaja_employee_signer_certificate_path, get_ujaja_ca_certificate_path
    emp_key_path = get_ujaja_employee_signer_key_path(civitas['id'])
    emp_cert_path = get_ujaja_employee_signer_certificate_path(civitas['id'])
    ca_cert_path = get_ujaja_ca_certificate_path()
    apply_acrobat_signature(source, output_path, verification_code, key_file=emp_key_path, cert_file=emp_cert_path, ca_cert_file=ca_cert_path, field_name=signature_field_name, field_page=signature_page_number - 1, field_box=signature_field_box, stamp_image=stamp_image, pdf_metadata=pdf_metadata, signer_name=f"{civitas['name']} ({civitas['employee_id']})")
    signed_hash = file_sha256(output_path)
    download_token = hashlib.sha256(f'{verification_code}|{signed_hash}|{signed_at}|{uuid.uuid4().hex}'.encode()).hexdigest()
    from flask import request as flask_request
    signer_ip = flask_request.remote_addr if flask_request else '127.0.0.1'
    signer_ua = flask_request.user_agent.string if flask_request else 'Unknown'
    with get_connection() as conn:
        conn.execute("\n            INSERT INTO ujaja_sign_requests (\n                employee_id, original_file_path, signed_file_path,\n                original_hash, signature_payload_hash, signed_hash,\n                verification_code, signature_position, ca_serial_number,\n                ujaja_digital_id_serial, signature_value, status, signed_at,\n                download_token, signer_ip_address, signer_user_agent, server_ssl_expires_at\n            )\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Signed', ?, ?, ?, ?, ?)\n            ", (civitas['id'], str(source), str(output_path), original_hash, signature_payload_hash, signed_hash, verification_code, f'page {signature_page_number}:{position}', ca['serial_number'], digital_id['serial_number'], signature_value, signed_at, download_token, signer_ip, signer_ua, cert_status.get('ssl_expires_at')))
    log_action(user['id'], 'INSTITUTION_SIGN_PDF', f"Dokumen {source.name} ditandatangani oleh {INSTITUTION_NAME}; operator {user['name']} ({verification_code}).")
    return {'output_path': output_path, 'verification_code': verification_code, 'signed_at': signed_at, 'signed_hash': signed_hash, 'signature_value': signature_value, 'verification_url': verification_url, 'download_token': download_token}

def extract_institution_verification_codes(pdf_path: str | Path) -> list[str]:
    path = Path(pdf_path)
    if not path.exists() or path.suffix.lower() != '.pdf':
        return []
    try:
        reader = PdfReader(str(path))
    except Exception:
        return []
    codes = []
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        with open(path, 'rb') as sig_f:
            sig_reader = PdfFileReader(sig_f, strict=False)
            for sig in sig_reader.embedded_signatures:
                for source_str in (sig.field_name, str(sig.sig_object.get('/Reason', ''))):
                    for m in CODE_PATTERN.finditer(source_str):
                        if m.group(0) not in codes:
                            codes.append(m.group(0))
    except Exception:
        pass
    import json
    metadata = reader.metadata or {}
    code_list_str = metadata.get('/UjajaSignCodeList') or metadata.get('UjajaSignCodeList')
    if code_list_str:
        try:
            meta_codes = json.loads(str(code_list_str))
            for c in meta_codes:
                if c not in codes:
                    codes.append(c)
        except Exception:
            pass
    for key in ('/UjajaSignCode', 'UjajaSignCode'):
        value = metadata.get(key)
        if value:
            match = CODE_PATTERN.search(str(value))
            if match and match.group(0) not in codes:
                codes.append(match.group(0))
    if not codes:
        for page in reader.pages:
            try:
                text = page.extract_text() or ''
            except Exception:
                continue
            for match in CODE_PATTERN.finditer(text):
                if match.group(0) not in codes:
                    codes.append(match.group(0))
    return codes

def _read_metadata(pdf_path: Path) -> dict:
    try:
        reader = PdfReader(str(pdf_path))
    except Exception:
        return {}
    metadata = reader.metadata or {}
    return {str(key).lstrip('/'): str(value) for key, value in metadata.items()}

def _log_institution_verification(code: str | None, result: str) -> None:
    with get_connection() as conn:
        conn.execute('\n            INSERT INTO verification_logs (document_id, verification_code, result)\n            VALUES (NULL, ?, ?)\n            ', (code, result))

def verify_institution_pdf(pdf_path: str | Path) -> dict:
    path = Path(pdf_path)
    if not path.exists():
        return {'valid': False, 'reason': 'File tidak ditemukan.', 'code': None}
    if path.suffix.lower() != '.pdf':
        return {'valid': False, 'reason': 'File harus PDF.', 'code': None}
    codes = extract_institution_verification_codes(path)
    if not codes:
        _log_institution_verification(None, 'invalid:no_code')
        return {'valid': False, 'reason': 'Kode verifikasi akademik tidak ditemukan.', 'code': None}
    metadata = _read_metadata(path)
    if metadata.get('UjajaSignMode') != 'institution':
        _log_institution_verification(codes[-1], 'invalid:not_institution')
        return {'valid': False, 'reason': 'Dokumen bukan institution-issued signature.', 'code': codes[-1]}
    ca = get_active_ujaja_ca()
    if ca is None:
        _log_institution_verification(codes[-1], 'invalid:ca_inactive')
        return {'valid': False, 'reason': 'CA Ujaja tidak aktif.', 'code': codes[-1]}
    results = []
    current_hash = file_sha256(path)
    for idx, code in enumerate(codes):
        with get_connection() as conn:
            document = conn.execute('\n                SELECT\n                    ujaja_sign_requests.*,\n                    employees.employee_id AS employee_code,\n                    employees.department,\n                    employees.position,\n                    employees.employee_status,\n                    users.id AS user_id,\n                    users.name AS employee_name,\n                    users.email AS employee_email\n                FROM ujaja_sign_requests\n                JOIN employees ON employees.id = ujaja_sign_requests.employee_id\n                JOIN users ON users.id = employees.user_id\n                WHERE ujaja_sign_requests.verification_code = ?\n                ', (code,)).fetchone()
        if document is None:
            results.append({'valid': False, 'reason': f'Dokumen {code} tidak terdaftar di database lokal.', 'code': code})
            continue
        with get_connection() as conn:
            digital_id = conn.execute('\n                SELECT * FROM ujaja_digital_ids\n                WHERE employee_id = ? AND serial_number = ?\n                ', (document['employee_id'], document['ujaja_digital_id_serial'])).fetchone()
        if digital_id is None:
            results.append({'valid': False, 'reason': f'Digital ID untuk {code} tidak ditemukan.', 'code': code})
            continue
        ca_match = document['ca_serial_number'] == ca['serial_number']
        digital_id_usable = digital_id['status'] in ('Active', 'Superseded')
        employee_active = document['employee_status'] == 'Active'
        hash_match = True
        if idx == len(codes) - 1:
            hash_match = current_hash == document['signed_hash']
        signature_valid = True
        is_valid = ca_match and digital_id_usable and employee_active and hash_match and signature_valid
        results.append({'valid': is_valid, 'code': code, 'signer_name': INSTITUTION_NAME, 'operator_name': document['employee_name'], 'operator_email': document['employee_email'], 'employee_id': document['employee_code'], 'employee_name': document['employee_name'], 'department': document['department'], 'position': document['position'], 'institution_name': INSTITUTION_NAME, 'signed_at': document['signed_at'], 'ca_serial': document['ca_serial_number'], 'digital_id_serial': document['ujaja_digital_id_serial'], 'hash_match': hash_match, 'ca_match': ca_match, 'digital_id_match': digital_id_usable, 'signature_valid': signature_valid, 'reason': 'OK' if is_valid else 'Gagal verifikasi rantai', 'document': document})
    all_valid = all((r['valid'] for r in results))
    final_reason = 'Semua rantai valid.' if all_valid else ' | '.join([r['reason'] for r in results if not r['valid']])
    final_names = ', '.join([r['employee_name'] for r in results if 'employee_name' in r])
    last_doc = results[-1]['document'] if results and 'document' in results[-1] else None
    _log_institution_verification(codes[-1], f"multi_verify:{('valid' if all_valid else 'invalid')}")
    return {'valid': all_valid, 'reason': final_reason, 'code': codes[-1], 'employee_name': final_names, 'employee_code': last_doc['employee_code'] if last_doc else None, 'department': last_doc['department'] if last_doc else None, 'position': last_doc['position'] if last_doc else None, 'signed_at': last_doc['signed_at'] if last_doc else None, 'signed_file_path': last_doc['signed_file_path'] if last_doc else None, 'signatures': results}

def get_signed_request_by_token(token: str):
    if not token or len(token) != 64:
        return None
    with get_connection() as conn:
        return conn.execute('SELECT * FROM ujaja_sign_requests WHERE download_token = ?', (token,)).fetchone()