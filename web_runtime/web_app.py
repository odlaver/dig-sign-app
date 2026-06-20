import hashlib
import os
import secrets
import subprocess
import sys
import uuid
from base64 import b64encode
from functools import wraps
from html import escape
from io import BytesIO
from pathlib import Path
from flask import Flask, abort, flash, redirect, render_template_string, request, send_file, session, url_for
from PIL import Image, ImageOps
import pypdfium2 as pdfium
from werkzeug.utils import secure_filename
from core.audit import list_recent_logs, log_action
from core.auth import get_user
from core.database import ASSETS_DIR, DATA_DIR, SIGNATURES_DIR, SIGNED_DOCS_DIR, TEMP_DIR, get_connection, init_db
from core.file_security import restrict_private_path
from core.otp_service import enable_otp, generate_qr_code
from core.security import hash_secret
from ujaja.ca_service import approve_civitas_digital_id_request, export_ujaja_employee_p12, get_ca_health, get_ujaja_ca, get_ujaja_employee_public_key_pem, get_ujaja_employee_signer_certificate_path, reject_civitas_digital_id_request, request_civitas_digital_id, verify_payload_signature
from ujaja.civitas_service import authenticate_civitas, ensure_institution_baseline_data, get_civitas_for_user, get_signature_profile, save_signature_profile
from ujaja.institution_signer import get_signed_request_by_token, sign_institution_pdf, verify_institution_pdf
from core.network_security import check_vpn_status, get_client_ip
UI_ASSETS_DIR = ASSETS_DIR / 'ui'
CSRF_SESSION_KEY = '_csrf_token'
CSRF_FIELD_NAME = '_csrf_token'
MAX_PREVIEW_PAGES = 20
WEB_SECRET_FILE = DATA_DIR / 'web_secret.key'

def _load_web_secret() -> str:
    configured = os.environ.get('UJAJA_WEB_SECRET')
    if configured:
        return configured
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if WEB_SECRET_FILE.exists():
        secret = WEB_SECRET_FILE.read_text(encoding='utf-8').strip()
        if secret:
            restrict_private_path(WEB_SECRET_FILE)
            return secret
    secret = secrets.token_urlsafe(48)
    WEB_SECRET_FILE.write_text(secret, encoding='utf-8')
    restrict_private_path(WEB_SECRET_FILE)
    return secret

def csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return str(token)

def csrf_input() -> str:
    return f'<input type="hidden" name="{CSRF_FIELD_NAME}" value="{escape(csrf_token())}">'

def csrf_valid() -> bool:
    token = session.get(CSRF_SESSION_KEY)
    submitted = request.form.get(CSRF_FIELD_NAME) or request.headers.get('X-CSRF-Token')
    return bool(token and submitted and secrets.compare_digest(str(token), str(submitted)))
BASE_TEMPLATE = '\n<!doctype html>\n<html lang="id">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <meta name="csrf-token" content="{{ csrf_token }}">\n  <title>{{ title }} - Ujaja Sign</title>\n  <link rel="preconnect" href="https://fonts.googleapis.com">\n  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">\n  <style>\n    :root {\n      --ujaja-blue: #0c2f86;\n      --ujaja-blue-700: #123f9f;\n      --ujaja-blue-900: #061b52;\n      --ujaja-sky: #eaf1ff;\n      --ujaja-sky-strong: #d6e4ff;\n      --slate: #4b5563;\n      --ink: #101828;\n      --muted: var(--slate);\n      --line: #d7deea;\n      --paper: #ffffff;\n      --surface: #f5f7fb;\n      --surface-strong: #eaf0fa;\n      --primary: var(--ujaja-blue);\n      --primary-dark: var(--ujaja-blue-900);\n      --accent: var(--ujaja-blue-700);\n      --accent-dark: var(--ujaja-blue-900);\n      --danger: #b42318;\n      --danger-dark: #7a271a;\n      --ok: #177245;\n      --warn: #8a6116;\n      --charcoal: var(--slate);\n      --mauve-shadow: var(--ujaja-blue);\n      --midnight-violet: var(--ujaja-blue-900);\n      --muted-teal: var(--ujaja-blue-700);\n      --dusty-olive: var(--ujaja-blue-700);\n      --font-sans: "Plus Jakarta Sans", "Segoe UI Variable", "Segoe UI", Arial, sans-serif;\n      --font-mono: "JetBrains Mono", Consolas, monospace;\n    }\n    * { box-sizing: border-box; }\n    body {\n      margin: 0;\n      font-family: var(--font-sans);\n      background: var(--surface);\n      color: var(--ink);\n    }\n    a { color: var(--primary); text-decoration: none; font-weight: 600; }\n    input, select, button, .button { font-family: inherit; }\n    .layout { min-height: 100vh; display: grid; grid-template-columns: 252px 1fr; }\n    .sidebar {\n      background: linear-gradient(180deg, var(--ujaja-blue-900) 0%, var(--ujaja-blue) 58%, var(--ujaja-blue-700) 100%);\n      border-right: 1px solid var(--ujaja-blue-900);\n      padding: 22px 18px;\n      position: sticky;\n      top: 0;\n      height: 100vh;\n      display: flex;\n      flex-direction: column;\n    }\n    .brand {\n      border-bottom: 4px solid var(--accent);\n      padding: 3px 0 18px;\n      font-weight: 700;\n      font-size: 19px;\n      color: #ffffff;\n      margin-bottom: 14px;\n    }\n    .login-logo {\n      width: 118px;\n      height: 118px;\n      object-fit: contain;\n      display: block;\n      margin: 0 auto 12px;\n    }\n    .account {\n      color: #eaf1ff;\n      font-size: 13px;\n      line-height: 1.45;\n      margin-bottom: 20px;\n      padding: 4px 2px 14px;\n      border-bottom: 1px solid rgba(255, 255, 255, .22);\n    }\n    .account-name {\n      display: block;\n      font-size: 14px;\n      font-weight: 600;\n      color: #ffffff;\n      margin-bottom: 2px;\n    }\n    .account-email {\n      display: block;\n      color: #cbd9f6;\n      word-break: break-word;\n    }\n    .nav a, .nav button {\n      display: block;\n      width: 100%;\n      border: 0;\n      background: transparent;\n      color: #f7fbff;\n      text-align: left;\n      padding: 10px 12px;\n      border-radius: 6px;\n      font-weight: 600;\n      font-size: 14px;\n      cursor: pointer;\n      margin-bottom: 3px;\n    }\n    .nav a:hover, .nav button:hover { background: rgba(255, 255, 255, .14); }\n    .logout-card {\n      margin-top: auto;\n      display: block;\n      background: var(--danger);\n      border: 1px solid var(--danger-dark);\n      color: #ffffff;\n      padding: 12px;\n      border-radius: 6px;\n      font-weight: 700;\n      text-align: center;\n      box-shadow: 0 1px 2px rgba(122, 39, 26, .24);\n    }\n    .logout-card:hover { background: var(--danger-dark); color: #ffffff; }\n    .main { padding: 24px 28px; max-width: 1180px; width: 100%; }\n    .topline {\n      background: var(--paper);\n      border: 1px solid var(--line);\n      border-left: 5px solid var(--accent);\n      border-radius: 6px;\n      padding: 18px 20px;\n      margin-bottom: 20px;\n      box-shadow: 0 1px 2px rgba(6, 27, 82, .06);\n    }\n    h1 { font-size: 26px; margin: 0; color: var(--midnight-violet); letter-spacing: 0; font-weight: 700; }\n    h2 { font-size: 18px; margin: 0 0 14px; color: var(--midnight-violet); font-weight: 700; }\n    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }\n    .panel, .stat {\n      background: var(--paper);\n      border: 1px solid var(--line);\n      border-radius: 6px;\n      padding: 18px;\n      box-shadow: 0 1px 2px rgba(6, 27, 82, .06);\n    }\n    .stat b { display: block; font-size: 26px; margin-top: 6px; font-weight: 700; color: var(--midnight-violet); }\n    .stat span { color: var(--muted); font-size: 12px; font-weight: 600; }\n    .stack { display: grid; gap: 16px; }\n    table {\n      width: 100%;\n      border-collapse: collapse;\n      background: var(--paper);\n      border: 1px solid var(--line);\n      border-radius: 6px;\n      box-shadow: 0 1px 2px rgba(6, 27, 82, .06);\n      overflow: hidden;\n    }\n    th, td { padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; font-size: 14px; vertical-align: top; }\n    th { color: var(--midnight-violet); font-size: 13px; font-weight: 600; letter-spacing: 0; background: var(--surface-strong); }\n    tr:last-child td { border-bottom: 0; }\n    label { display: block; font-weight: 600; margin: 0 0 6px; font-size: 13px; color: var(--mauve-shadow); }\n    input, select {\n      width: 100%;\n      max-width: 460px;\n      padding: 10px 12px;\n      border: 1px solid #c8d2e5;\n      border-radius: 5px;\n      background: #fff;\n      color: var(--ink);\n      font-size: 14px;\n      font-weight: 500;\n    }\n    input:disabled { background: #edf1f7; color: var(--charcoal); }\n    input[type=file] { padding: 8px; }\n    .signature-grid {\n      display: grid;\n      grid-template-columns: minmax(240px, 360px) minmax(260px, 1fr);\n      gap: 18px;\n      align-items: start;\n    }\n    .signature-preview {\n      min-height: 148px;\n      border: 1px solid var(--line);\n      border-radius: 6px;\n      background: #f8fbff;\n      display: grid;\n      place-items: center;\n      padding: 18px;\n    }\n    .signature-preview img {\n      max-width: 100%;\n      max-height: 118px;\n      object-fit: contain;\n      display: block;\n    }\n    .signature-empty {\n      color: var(--muted);\n      font-weight: 600;\n      text-align: center;\n      line-height: 1.5;\n    }\n    .placement-grid {\n      display: grid;\n      grid-template-columns: minmax(280px, 520px) minmax(260px, 1fr);\n      gap: 20px;\n      align-items: start;\n    }\n    .placement-shell {\n      background: var(--ujaja-sky);\n      border: 1px solid #c4d2eb;\n      border-radius: 6px;\n      padding: 18px;\n    }\n    .pdf-scroll {\n      max-height: min(72vh, 760px);\n      overflow-y: auto;\n      overscroll-behavior: contain;\n      display: grid;\n      gap: 16px;\n      padding: 10px;\n      border: 1px solid #c4d2eb;\n      border-radius: 6px;\n      background: #f1f5fc;\n    }\n    .pdf-page-card {\n      display: grid;\n      gap: 8px;\n    }\n    .pdf-page-label {\n      color: var(--mauve-shadow);\n      font-size: 12px;\n      font-weight: 600;\n      text-align: center;\n    }\n    .pdf-page-card.is-active .pdf-page-label {\n      color: var(--primary);\n    }\n    .placement-page {\n      position: relative;\n      width: min(100%, 430px);\n      aspect-ratio: 210 / 297;\n      margin: 0 auto;\n      background:\n        linear-gradient(#ffffff, #ffffff) padding-box,\n        linear-gradient(135deg, var(--ujaja-sky-strong), #ffffff) border-box;\n      border: 1px solid #b8c7df;\n      border-radius: 4px;\n      box-shadow: 0 8px 18px rgba(6, 27, 82, .12);\n      overflow: hidden;\n      cursor: crosshair;\n      user-select: none;\n      touch-action: none;\n    }\n    .pdf-page-card.is-active .placement-page {\n      border-color: var(--primary);\n      box-shadow: 0 8px 18px rgba(12, 47, 134, .22);\n    }\n    .placement-page.has-preview::before,\n    .placement-page.has-preview::after {\n      display: none;\n    }\n    .placement-page::before {\n      content: "";\n      position: absolute;\n      inset: 30px;\n      border-top: 8px solid var(--ujaja-sky-strong);\n      border-bottom: 8px solid var(--ujaja-sky-strong);\n      opacity: .75;\n      pointer-events: none;\n    }\n    .placement-page::after {\n      content: "";\n      position: absolute;\n      left: 30px;\n      right: 30px;\n      top: 84px;\n      height: 220px;\n      background: repeating-linear-gradient(\n        to bottom,\n        #e7eef9 0,\n        #e7eef9 5px,\n        transparent 5px,\n        transparent 21px\n      );\n      pointer-events: none;\n    }\n    .pdf-preview-image {\n      position: absolute;\n      inset: 0;\n      width: 100%;\n      height: 100%;\n      object-fit: fill;\n      display: none;\n      z-index: 1;\n      pointer-events: none;\n      background: #ffffff;\n    }\n    .placement-page.has-preview .pdf-preview-image {\n      display: block;\n    }\n    .pdf-preview-empty {\n      position: absolute;\n      inset: 0;\n      display: grid;\n      place-items: center;\n      color: var(--muted);\n      font-size: 13px;\n      font-weight: 600;\n      z-index: 1;\n      pointer-events: none;\n      text-align: center;\n      padding: 24px;\n    }\n    .placement-page.has-preview .pdf-preview-empty {\n      display: none;\n    }\n    .signature-marker {\n      position: absolute;\n      left: 0;\n      top: 0;\n      width: 30%;\n      aspect-ratio: 1763 / 892;\n      min-width: 92px;\n      min-height: 48px;\n      border: 1px dashed rgba(12, 47, 134, .58);\n      border-radius: 4px;\n      background: rgba(255, 255, 255, .04);\n      box-shadow: none;\n      cursor: grab;\n      display: grid;\n      grid-template-columns: minmax(0, 1fr) 34%;\n      grid-template-rows: 1fr;\n      gap: 4%;\n      align-items: center;\n      padding: 4px;\n      z-index: 3;\n      touch-action: none;\n    }\n    .signature-marker:active { cursor: grabbing; }\n    .signature-marker:focus-visible {\n      outline: 2px solid var(--primary);\n      outline-offset: 2px;\n    }\n    .signature-stamp-image {\n      width: 100%;\n      height: 100%;\n      object-fit: contain;\n      display: block;\n      pointer-events: none;\n      user-select: none;\n    }\n    .signature-preview-signature {\n      min-width: 0;\n      height: 100%;\n      position: relative;\n    }\n    .signature-preview-cap,\n    .signature-preview-autograph {\n      position: absolute;\n      inset: 0;\n      width: 100%;\n      height: 100%;\n      object-fit: contain;\n      pointer-events: none;\n      user-select: none;\n    }\n    .signature-preview-autograph {\n      transform: scale(.72);\n      opacity: .92;\n    }\n    .signature-preview-qr {\n      width: 100%;\n      aspect-ratio: 1;\n      align-self: center;\n      justify-self: end;\n      border: 1px solid rgba(12, 47, 134, .42);\n      background:\n        linear-gradient(90deg, #111827 50%, transparent 0) 0 0/18% 18%,\n        linear-gradient(#111827 50%, transparent 0) 0 0/18% 18%,\n        #ffffff;\n      pointer-events: none;\n    }\n    .signature-resize-handle {\n      position: absolute;\n      right: -5px;\n      bottom: -5px;\n      width: 14px;\n      height: 14px;\n      border: 2px solid #ffffff;\n      border-radius: 50%;\n      background: var(--primary);\n      box-shadow: 0 1px 4px rgba(6, 27, 82, .28);\n      cursor: nwse-resize;\n      touch-action: none;\n    }\n    .placement-coords {\n      margin-top: 12px;\n      display: flex;\n      gap: 8px;\n      flex-wrap: wrap;\n      color: var(--muted);\n      font-size: 12px;\n      font-weight: 600;\n    }\n    .field { margin-bottom: 14px; }\n    .actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }\n    button, .button {\n      border: 1px solid var(--primary-dark);\n      border-radius: 5px;\n      background: var(--primary);\n      color: #fff;\n      padding: 10px 14px;\n      font-weight: 600;\n      cursor: pointer;\n      display: inline-block;\n    }\n    button:hover, .button:hover { background: var(--primary-dark); color: #fff; }\n    button:disabled {\n      background: var(--dusty-olive);\n      border-color: var(--dusty-olive);\n      cursor: not-allowed;\n      opacity: .7;\n    }\n    .danger { background: var(--danger); }\n    .danger:hover { background: var(--danger-dark); }\n    .muted { color: var(--muted); }\n    .badge {\n      display: inline-block;\n      padding: 4px 8px;\n      border-radius: 999px;\n      border: 1px solid #c8d2e5;\n      font-size: 12px;\n      font-weight: 600;\n      background: var(--ujaja-sky);\n      color: var(--midnight-violet);\n    }\n    .account .badge {\n      margin-top: 8px;\n      background: rgba(255, 255, 255, .14);\n      color: #ffffff;\n      border-color: rgba(255, 255, 255, .28);\n      border-radius: 4px;\n      padding: 3px 7px;\n      font-size: 11px;\n      text-transform: uppercase;\n    }\n    .badge.ok { background: #eaf8f0; color: var(--ok); border-color: #acd9bf; }\n    .badge.warn { background: #fff7e8; color: var(--warn); border-color: #efd49b; }\n    .badge.danger { background: #fff0ee; color: var(--danger); border-color: #f1b7b0; }\n    .flash { margin-bottom: 16px; padding: 12px 14px; border-radius: 6px; border: 1px solid #c8d2e5; background: #fff; font-weight: 500; }\n    .login-page {\n      min-height: 100svh;\n      display: grid;\n      place-items: center;\n      padding: clamp(18px, 7vw, 72px);\n      background:\n        linear-gradient(rgba(255, 255, 255, .62), rgba(255, 255, 255, .62)),\n        url("{{ url_for(\'login_background_image\') }}") center / 340px auto repeat;\n    }\n    .login-shell {\n      width: min(860px, 100%);\n      display: grid;\n      grid-template-columns: minmax(250px, 1fr) minmax(286px, .92fr);\n      background: var(--paper);\n      border: 1px solid rgba(199, 210, 229, .88);\n      border-radius: 8px;\n      box-shadow: 0 18px 42px rgba(6, 27, 82, .13);\n      overflow: hidden;\n    }\n    .login-visual {\n      position: relative;\n      min-height: 500px;\n      background:\n        linear-gradient(180deg, rgba(6, 27, 82, .02) 0%, rgba(6, 27, 82, .56) 100%),\n        url("{{ url_for(\'login_photo_image\') }}") center / 108% auto no-repeat;\n    }\n    .login-visual::after {\n      content: "";\n      position: absolute;\n      inset: 0;\n      background: linear-gradient(180deg, rgba(255, 255, 255, 0) 62%, rgba(6, 27, 82, .16) 100%);\n      pointer-events: none;\n    }\n    .login-content {\n      display: grid;\n      align-content: center;\n      justify-items: center;\n      padding: 34px clamp(28px, 5vw, 50px);\n      text-align: center;\n    }\n    .login-stack {\n      width: 100%;\n      display: grid;\n      justify-items: center;\n      transform: translateY(-10px);\n    }\n    .login-content .login-logo {\n      width: 86px;\n      height: 62px;\n      margin: 0 auto 12px;\n      object-fit: contain;\n    }\n    .login-heading {\n      margin: 0 0 36px;\n      color: #7d8494;\n      font-size: 22px;\n      line-height: 1.22;\n      font-weight: 400;\n      letter-spacing: 0;\n      text-align: center;\n    }\n    .login-heading strong {\n      display: block;\n      margin-top: 3px;\n      color: var(--ujaja-blue);\n      font-size: 28px;\n      line-height: 1.14;\n      font-weight: 600;\n    }\n    .login-title {\n      margin: 0;\n      color: var(--ink);\n      font-size: 25px;\n      line-height: 1.14;\n      font-weight: 500;\n    }\n    .login-title strong {\n      display: block;\n      color: #050b1c;\n      font-size: 33px;\n      font-weight: 700;\n      margin-top: 5px;\n    }\n    .login-form-box {\n      width: 100%;\n      max-width: 380px;\n      margin-top: 0;\n      border: 0;\n      border-radius: 0;\n      background: transparent;\n      padding: 0;\n      text-align: left;\n      box-shadow: none;\n    }\n    .login-form-heading {\n      margin: 0 0 20px;\n      color: #475467;\n      text-align: center;\n      font-size: 15px;\n      line-height: 1.1;\n      font-weight: 600;\n      letter-spacing: 0;\n    }\n    .login-form-box input {\n      max-width: none;\n      border: 0;\n      border-radius: 0;\n      background: transparent;\n      padding: 0;\n      color: var(--ujaja-blue-900);\n      font-size: 16px;\n      font-weight: 500;\n      line-height: 1.45;\n      outline: 0;\n    }\n    .login-form-box input::placeholder {\n      color: #98a2b3;\n      font-weight: 500;\n      opacity: 1;\n    }\n    .login-field {\n      display: grid;\n      grid-template-columns: 28px minmax(0, 1fr) 28px;\n      align-items: center;\n      column-gap: 14px;\n      border-bottom: 1px solid #d5dbe6;\n      padding: 0 0 12px;\n      margin-bottom: 24px;\n    }\n    .login-field svg {\n      width: 22px;\n      height: 22px;\n      color: var(--ujaja-blue);\n      stroke-width: 2.6;\n    }\n    .login-field-password { margin-bottom: 22px; }\n    .login-field-spacer {\n      width: 28px;\n      height: 1px;\n    }\n    .password-toggle {\n      width: 28px;\n      height: 28px;\n      display: grid;\n      place-items: center;\n      border: 0;\n      background: transparent;\n      color: #111827;\n      padding: 0;\n      margin: 0;\n      cursor: pointer;\n    }\n    .password-toggle:hover {\n      background: transparent;\n      color: var(--ujaja-blue);\n    }\n    .sr-only {\n      position: absolute;\n      width: 1px;\n      height: 1px;\n      padding: 0;\n      margin: -1px;\n      overflow: hidden;\n      clip: rect(0, 0, 0, 0);\n      white-space: nowrap;\n      border: 0;\n    }\n    .login-form-box > button {\n      width: auto;\n      min-width: 132px;\n      justify-content: center;\n      border-radius: 4px;\n      margin: 8px auto 0;\n      padding: 10px 16px;\n      background: var(--ujaja-blue);\n      border-color: var(--ujaja-blue);\n      display: block;\n      font-size: 14px;\n      line-height: 1.35;\n    }\n    .login-form-box > button:hover {\n      background: var(--ujaja-blue-900);\n      border-color: var(--ujaja-blue-900);\n    }\n    .login-card { width: min(440px, 100%); display: block; }\n    .seed-list { display: grid; gap: 10px; }\n    .seed { padding: 12px; border: 1px solid var(--line); border-radius: 6px; background: #fff; }\n    .seed strong { display: block; }\n    @media (min-width: 821px) and (max-height: 700px) {\n      .login-page { padding: 18px; }\n      .login-shell {\n        width: min(780px, 100%);\n        grid-template-columns: minmax(240px, 1fr) minmax(270px, .9fr);\n      }\n      .login-visual { min-height: 440px; }\n      .login-content { padding: 28px 34px; }\n      .login-stack { transform: translateY(-8px); }\n      .login-content .login-logo { width: 72px; height: 52px; margin-bottom: 9px; }\n      .login-heading { margin-bottom: 26px; font-size: 19px; }\n      .login-heading strong { font-size: 24px; }\n      .login-title { font-size: 21px; }\n      .login-title strong { font-size: 27px; }\n      .login-form-box { margin-top: 0; padding: 0; }\n      .field { margin-bottom: 10px; }\n    }\n    @media (max-width: 820px) {\n      .layout { grid-template-columns: 1fr; }\n      .sidebar { position: static; height: auto; }\n      .main { padding: 18px; }\n      .grid, .signature-grid, .placement-grid, .login-card { grid-template-columns: 1fr; }\n      .login-page { padding: 18px; }\n      .login-shell {\n        width: min(540px, 100%);\n        grid-template-columns: minmax(210px, 1fr) minmax(236px, .86fr);\n      }\n      .login-visual { min-height: 420px; }\n      .login-content { padding: 26px 24px; }\n      .login-stack { transform: translateY(-8px); }\n      .login-content .login-logo { width: 104px; height: 74px; margin-bottom: 12px; }\n      .login-heading { margin-bottom: 28px; font-size: 20px; }\n      .login-heading strong { font-size: 25px; }\n      .login-title { font-size: 19px; }\n      .login-title strong { font-size: 24px; margin-top: 3px; }\n      .login-form-box { margin-top: 0; padding: 0; }\n      .login-form-heading { margin-bottom: 14px; font-size: 14px; }\n      .login-form-box .field { margin-bottom: 10px; }\n      .signature-marker { width: 34%; }\n      table { display: block; overflow-x: auto; }\n    }\n    @media (max-width: 640px) {\n      .login-page { padding: 14px; }\n      .login-shell {\n        width: min(430px, 100%);\n        grid-template-columns: 1fr;\n      }\n      .login-visual {\n        min-height: 0;\n        aspect-ratio: 16 / 9;\n        background:\n          linear-gradient(180deg, rgba(6, 27, 82, .04) 0%, rgba(6, 27, 82, .38) 100%),\n          url("{{ url_for(\'login_photo_image\') }}") center 48% / cover no-repeat;\n      }\n      .login-content { padding: 24px 28px 28px; }\n      .login-stack { transform: none; }\n      .login-heading { margin-bottom: 28px; font-size: 20px; }\n      .login-heading strong { font-size: 25px; }\n      .login-title { font-size: 20px; }\n      .login-title strong { font-size: 25px; }\n      .login-form-box { max-width: 350px; }\n    }\n    @media (max-width: 500px) {\n      .login-shell { width: min(370px, 100%); }\n      .login-content { padding: 24px 22px 26px; }\n      .login-form-box { max-width: none; }\n    }\n  </style>\n</head>\n<body>\n  {% if user %}\n  <div class="layout">\n    <aside class="sidebar">\n      <div class="brand"><span>UJAJA SIGN</span></div>\n      <div class="account">\n        <span class="account-name">{{ user["name"] }}</span>\n        <span class="account-email">{{ user["email"] }}</span>\n        <span class="badge">{{ user["role"] }}</span>\n      </div>\n      <nav class="nav">\n        <a href="{{ url_for(\'dashboard\') }}">Dashboard</a>\n        {% if is_admin %}\n          <a href="{{ url_for(\'otp_page\') }}">Setup OTP</a>\n          <a href="{{ url_for(\'admin_requests\') }}">Digital ID Requests</a>\n          <a href="{{ url_for(\'admin_certificates\') }}">Certificates</a>\n          <a href="{{ url_for(\'admin_audit\') }}">Audit Logs</a>\n        {% else %}\n          <a href="{{ url_for(\'set_signature_page\') }}">Set Signature</a>\n          <a href="{{ url_for(\'otp_page\') }}">Setup OTP</a>\n          <a href="{{ url_for(\'request_digital_id_page\') }}">Request Digital ID</a>\n          <a href="{{ url_for(\'digital_id_page\') }}">Digital ID Status</a>\n          <a href="{{ url_for(\'sign_page\') }}">Sign PDF</a>\n          <a href="{{ url_for(\'sign_history_page\') }}">Sign History</a>\n          <a href="{{ url_for(\'verify_page\') }}">Verify PDF</a>\n        {% endif %}\n      </nav>\n      <a class="logout-card" href="{{ url_for(\'logout\') }}">Logout</a>\n    </aside>\n    <main class="main">\n      <div class="topline"><h1>{{ title }}</h1></div>\n      {% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}\n      {{ body|safe }}\n    </main>\n  </div>\n  {% else %}\n    {{ body|safe }}\n  {% endif %}\n</body>\n</html>\n'

def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = _load_web_secret()
    app.config['MAX_CONTENT_LENGTH'] = 40 * 1024 * 1024
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=True)
    init_db()
    ensure_institution_baseline_data()

    def _is_secure_request() -> bool:
        return request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'

    def current_user():
        user_id = session.get('user_id')
        return get_user(int(user_id)) if user_id else None

    def user_count() -> int:
        with get_connection() as conn:
            row = conn.execute('SELECT COUNT(*) AS total FROM users').fetchone()
            return int(row['total'])

    def setup_required() -> bool:
        return user_count() == 0

    def is_admin_user(user) -> bool:
        return bool(user and user['role'] == 'admin')

    def current_signature_path(user_id: int) -> Path | None:
        profile_path = get_signature_profile(user_id)
        if not profile_path:
            return None
        path = Path(profile_path)
        if not path.exists() or path.suffix.lower() not in {'.png', '.jpg', '.jpeg'}:
            return None
        return path

    def prepare_signature_image(image: Image.Image) -> Image.Image:
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

    def page(title: str, body: str):
        user = current_user()
        return render_template_string(BASE_TEMPLATE, title=title, body=body, user=user, is_admin=is_admin_user(user), messages=[m for _, m in list(session.pop('_flashes', []))], csrf_token=csrf_token())

    @app.before_request
    def enforce_https():
        if not _is_secure_request():
            return ('HTTPS diperlukan untuk mengakses aplikasi ini.', 403)

    @app.before_request
    def protect_unsafe_methods():
        if request.method != 'POST':
            return None
        if csrf_valid():
            return None
        if request.path == '/pdf/placement-preview':
            return ({'error': 'Sesi form tidak valid. Muat ulang halaman.'}, 400)
        flash('Sesi form tidak valid. Muat ulang halaman lalu coba lagi.')
        if current_user() is None:
            return redirect(url_for('login'))
        return redirect(url_for('dashboard'))

    @app.get('/ui/logo')
    def logo_image():
        path = UI_ASSETS_DIR / 'logo_ujaja.png'
        if not path.exists():
            return ('', 404)
        return send_file(path)

    @app.get('/ui/login-background')
    def login_background_image():
        path = UI_ASSETS_DIR / 'background.jpg'
        if not path.exists():
            return ('', 404)
        return send_file(path)

    @app.get('/ui/login-photo')
    def login_photo_image():
        path = UI_ASSETS_DIR / 'loginpage_img.jpg'
        if not path.exists():
            return ('', 404)
        return send_file(path)

    @app.get('/ui/cap')
    def cap_image():
        path = UI_ASSETS_DIR / 'cap_ujaja.jpg'
        if not path.exists():
            return ('', 404)
        try:
            with Image.open(path) as image:
                prepared = prepare_signature_image(image)
                output = BytesIO()
                prepared.save(output, format='PNG', optimize=True)
                output.seek(0)
                return send_file(output, mimetype='image/png')
        except Exception:
            return send_file(path)

    def require_login(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            if setup_required():
                return redirect(url_for('setup_admin'))
            if current_user() is None:
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        return wrapper

    def require_admin(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not is_admin_user(user):
                flash('Akses hanya untuk Admin CA.')
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)
        return wrapper

    def require_otp_enabled(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for('login'))
            if not user['otp_enabled']:
                flash('Aktifkan OTP terlebih dahulu sebelum mengakses fitur Digital ID.')
                return redirect(url_for('otp_page'))
            return func(*args, **kwargs)
        return wrapper

    def require_signature_profile(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for('login'))
            if is_admin_user(user):
                return func(*args, **kwargs)
            if current_signature_path(user['id']) is None:
                flash('Set Signature terlebih dahulu sebelum setup OTP dan request Digital ID.')
                return redirect(url_for('set_signature_page'))
            return func(*args, **kwargs)
        return wrapper

    def save_upload(upload, prefix: str) -> Path:
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        filename = secure_filename(upload.filename or 'upload.pdf')
        target = TEMP_DIR / f'{prefix}_{uuid.uuid4().hex}_{filename}'
        upload.save(target)
        return target

    def save_signature_upload(upload, user_id: int) -> Path:
        if not upload or not upload.filename:
            raise ValueError('Pilih file gambar signature dulu.')
        filename = secure_filename(upload.filename)
        suffix = Path(filename).suffix.lower()
        if suffix not in {'.png', '.jpg', '.jpeg'}:
            raise ValueError('Format signature harus PNG, JPG, atau JPEG.')
        try:
            with Image.open(upload.stream) as image:
                image.verify()
            upload.stream.seek(0)
            with Image.open(upload.stream) as image:
                image = ImageOps.exif_transpose(image)
                width, height = image.size
                if width < 40 or height < 20:
                    raise ValueError('Ukuran gambar signature terlalu kecil.')
                if width > 6000 or height > 6000:
                    raise ValueError('Ukuran gambar signature terlalu besar.')
                image = prepare_signature_image(image)
                image.thumbnail((1800, 900))
                SIGNATURES_DIR.mkdir(parents=True, exist_ok=True)
                target = SIGNATURES_DIR / f'user_{user_id}_{uuid.uuid4().hex}.png'
                image.save(target, format='PNG', optimize=True)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError('File signature tidak bisa dibaca sebagai gambar.') from exc
        old_path = current_signature_path(user_id)
        save_signature_profile(user_id, str(target))
        if old_path and old_path.resolve().parent == SIGNATURES_DIR.resolve() and (old_path != target):
            old_path.unlink(missing_ok=True)
        return target

    def signature_position_from_form() -> str:
        try:
            x_percent = float(request.form.get('position_x', '100'))
            y_percent = float(request.form.get('position_y', '100'))
        except ValueError as exc:
            raise ValueError('Posisi signature tidak valid.') from exc
        x_percent = max(0.0, min(100.0, x_percent))
        y_percent = max(0.0, min(100.0, y_percent))
        return f'custom:{x_percent:.2f}:{y_percent:.2f}'

    def signature_size_from_form() -> tuple[float, float]:
        try:
            width_percent = float(request.form.get('signature_width', '30'))
            height_percent = float(request.form.get('signature_height', '9'))
        except ValueError as exc:
            raise ValueError('Ukuran signature tidak valid.') from exc
        width_percent = max(12.0, min(75.0, width_percent))
        height_percent = max(4.0, min(34.0, height_percent))
        return (width_percent, height_percent)

    def render_pdf_placement_previews(upload):
        if not upload or not upload.filename:
            raise ValueError('Pilih PDF dulu.')
        if Path(upload.filename).suffix.lower() != '.pdf':
            raise ValueError('File preview harus PDF.')
        pdf_bytes = upload.read()
        if not pdf_bytes:
            raise ValueError('File PDF kosong.')
        pdf = None
        try:
            pdf = pdfium.PdfDocument(pdf_bytes)
            page_count = len(pdf)
            if page_count < 1:
                raise ValueError('PDF tidak memiliki halaman.')
            pages = []
            preview_count = min(page_count, MAX_PREVIEW_PAGES)
            for index in range(preview_count):
                page = None
                try:
                    page = pdf.get_page(index)
                    page_width, page_height = page.get_size()
                    longest_side = max(page_width, page_height, 1)
                    scale = min(1.35, 1200 / longest_side)
                    bitmap = page.render(scale=scale)
                    image = bitmap.to_pil()
                    if image.mode != 'RGB':
                        image = image.convert('RGB')
                    output = BytesIO()
                    image.save(output, format='JPEG', quality=84, optimize=True)
                    image_data = b64encode(output.getvalue()).decode('ascii')
                    pages.append({'number': index + 1, 'width': page_width, 'height': page_height, 'image': f'data:image/jpeg;base64,{image_data}'})
                finally:
                    if page is not None:
                        page.close()
            return {'page_count': page_count, 'preview_count': preview_count, 'truncated': page_count > preview_count, 'pages': pages}
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError('Preview PDF tidak bisa dibuat.') from exc
        finally:
            if pdf is not None:
                pdf.close()

    def get_signed_request_for_user(request_id: int):
        user = current_user()
        if user is None:
            return None
        with get_connection() as conn:
            if is_admin_user(user):
                return conn.execute('\n                    SELECT ujaja_sign_requests.*, employees.user_id, users.name AS employee_name\n                    FROM ujaja_sign_requests\n                    JOIN employees ON employees.id = ujaja_sign_requests.employee_id\n                    JOIN users ON users.id = employees.user_id\n                    WHERE ujaja_sign_requests.id = ?\n                    ', (request_id,)).fetchone()
            return conn.execute('\n                SELECT ujaja_sign_requests.*, employees.user_id, users.name AS employee_name\n                FROM ujaja_sign_requests\n                JOIN employees ON employees.id = ujaja_sign_requests.employee_id\n                JOIN users ON users.id = employees.user_id\n                WHERE ujaja_sign_requests.id = ? AND employees.user_id = ?\n                ', (request_id, user['id'])).fetchone()

    def get_signed_file_for_user(filename: str):
        user = current_user()
        if user is None:
            return None
        with get_connection() as conn:
            if is_admin_user(user):
                rows = conn.execute('SELECT * FROM ujaja_sign_requests').fetchall()
            else:
                rows = conn.execute('\n                    SELECT ujaja_sign_requests.*\n                    FROM ujaja_sign_requests\n                    JOIN employees ON employees.id = ujaja_sign_requests.employee_id\n                    WHERE employees.user_id = ?\n                    ', (user['id'],)).fetchall()
        for row in rows:
            signed_path = Path(row['signed_file_path'] or '')
            if signed_path.name == filename:
                return row
        return None

    def open_local_path(path: Path) -> None:
        if os.name == 'nt':
            os.startfile(str(path))
            return
        command = ['open', str(path)] if sys.platform == 'darwin' else ['xdg-open', str(path)]
        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @app.get('/')
    def index():
        if setup_required():
            return redirect(url_for('setup_admin'))
        return redirect(url_for('dashboard') if current_user() else url_for('login'))

    @app.route('/setup', methods=['GET', 'POST'])
    def setup_admin():
        if not setup_required():
            return redirect(url_for('login'))
        if request.method == 'POST':
            name = (request.form.get('name') or '').strip()
            email = (request.form.get('email') or '').strip().lower()
            password = request.form.get('password') or ''
            confirm = request.form.get('confirm') or ''
            if not name:
                flash('Nama admin wajib diisi.')
                return redirect(url_for('setup_admin'))
            if '@' not in email:
                flash('Email admin tidak valid.')
                return redirect(url_for('setup_admin'))
            if len(password) < 8:
                flash('Password admin minimal 8 karakter.')
                return redirect(url_for('setup_admin'))
            if password != confirm:
                flash('Konfirmasi password tidak cocok.')
                return redirect(url_for('setup_admin'))
            with get_connection() as conn:
                cursor = conn.execute("\n                    INSERT INTO users (name, email, password_hash, role)\n                    VALUES (?, ?, ?, 'admin')\n                    ", (name, email, hash_secret(password)))
                session['user_id'] = int(cursor.lastrowid)
            return redirect(url_for('dashboard'))
        body = f'\n        <div class="login-page">\n          <div class="login-shell">\n            <div class="login-visual" aria-hidden="true"></div>\n            <section class="login-content">\n              <div class="login-stack">\n                <img class="login-logo" src="/ui/logo" alt="">\n                <form class="login-form-box" method="post">\n                  {csrf_input()}\n                  <h2 class="login-form-heading">SETUP ADMIN</h2>\n                  <div class="field"><label for="setup-name">Nama</label><input id="setup-name" name="name" placeholder="Nama admin" required></div>\n                  <div class="field"><label for="setup-email">Email</label><input id="setup-email" name="email" autocomplete="username" placeholder="admin@ujaja.ac.id" required></div>\n                  <div class="field"><label for="setup-password">Password</label><input id="setup-password" name="password" type="password" autocomplete="new-password" placeholder="Minimal 8 karakter" minlength="8" required></div>\n                  <div class="field"><label for="setup-confirm">Konfirmasi Password</label><input id="setup-confirm" name="confirm" type="password" autocomplete="new-password" placeholder="Ulangi password" minlength="8" required></div>\n                  <button type="submit">Buat Admin</button>\n                </form>\n              </div>\n            </section>\n          </div>\n        </div>\n        '
        return page('Setup Admin', body)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if setup_required():
            return redirect(url_for('setup_admin'))
        if request.method == 'POST':
            from core.network_security import check_vpn_status
            net_check = check_vpn_status(request)
            if net_check.get('is_blocked'):
                log_action(None, 'LOGIN_FAILED', f"Akses diblokir: VPN / Proxy Detected. Reason: {net_check.get('reason')}", status='FAILED')
                flash('VPN / Proxy Detected. Please Disable VPN Before Accessing This System.')
                return redirect(url_for('login'))
            result, error = authenticate_civitas(request.form.get('email', ''), request.form.get('password', ''))
            if error:
                log_action(None, 'LOGIN_FAILED', f'Login gagal: {error}', status='FAILED')
                flash(error)
                return redirect(url_for('login'))
            session['user_id'] = int(result['user']['id'])
            log_action(result['user']['id'], 'LOGIN_SUCCESS', 'Berhasil login ke sistem', status='SUCCESS')
            return redirect(url_for('dashboard'))
        body = f"""\n        <div class="login-page">\n          <div class="login-shell">\n            <div class="login-visual" aria-hidden="true"></div>\n            <section class="login-content">\n              <div class="login-stack">\n                <img class="login-logo" src="/ui/logo" alt="">\n                <h1 class="login-heading">\n                  Digital Sign App\n                  <strong>Universitas Jaya Jaya</strong>\n                </h1>\n                <form class="login-form-box" method="post">\n                  {csrf_input()}\n                  <div class="login-field">\n                    <svg viewBox="0 0 24 24" aria-hidden="true" fill="currentColor"><path d="M12 12c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5Zm0 2c-4.42 0-8 2.24-8 5v1.2c0 .44.36.8.8.8h14.4c.44 0 .8-.36.8-.8V19c0-2.76-3.58-5-8-5Z"></path></svg>\n                    <label class="sr-only" for="login-email">Email</label>\n                    <input id="login-email" name="email" autocomplete="username" placeholder="Masukkan Akun Pengguna" required>\n                    <span class="login-field-spacer" aria-hidden="true"></span>\n                  </div>\n                  <div class="login-field login-field-password">\n                    <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="14.5" r="4.5"></circle><path d="m11 11 9-9"></path><path d="m16 6 2 2"></path><path d="m14 8 2 2"></path></svg>\n                    <label class="sr-only" for="login-password">Password</label>\n                    <input id="login-password" name="password" type="password" autocomplete="current-password" placeholder="Masukkan Kata Sandi" required>\n                    <button class="password-toggle" type="button" aria-label="Tampilkan password" onclick="const input=document.getElementById('login-password'); const showing=input.type==='text'; input.type=showing?'password':'text'; this.setAttribute('aria-label', showing?'Tampilkan password':'Sembunyikan password');">\n                      <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z"></path><circle cx="12" cy="12" r="3"></circle><path d="M3 21 21 3"></path></svg>\n                    </button>\n                  </div>\n                  <button type="submit">Masuk</button>\n                </form>\n              </div>\n            </section>\n          </div>\n        </div>\n        """
        return page('Login', body)

    @app.get('/logout')
    def logout():
        user = current_user()
        if user:
            log_action(user['id'], 'LOGOUT', 'Berhasil logout', status='SUCCESS')
        session.clear()
        return redirect(url_for('login'))

    @app.get('/dashboard')
    @require_login
    def dashboard():
        user = current_user()
        health = get_ca_health()
        if is_admin_user(user):
            with get_connection() as conn:
                stats = {'civitas': conn.execute("SELECT COUNT(*) FROM users WHERE role IN ('employee', 'dosen', 'mahasiswa', 'dekanat')").fetchone()[0], 'pending': conn.execute("SELECT COUNT(*) FROM ujaja_digital_ids WHERE status = 'Pending' AND employee_id IS NOT NULL").fetchone()[0], 'active': conn.execute("SELECT COUNT(*) FROM ujaja_digital_ids WHERE status = 'Active' AND employee_id IS NOT NULL").fetchone()[0], 'docs': conn.execute('SELECT COUNT(*) FROM ujaja_sign_requests').fetchone()[0]}
            body = f"""\n            <div class="grid">\n              <div class="stat"><span>Total Civitas</span><b>{stats['civitas']}</b></div>\n              <div class="stat"><span>Pending Requests</span><b>{stats['pending']}</b></div>\n              <div class="stat"><span>Digital ID Aktif</span><b>{stats['active']}</b></div>\n              <div class="stat"><span>Dokumen Signed</span><b>{stats['docs']}</b></div>\n            </div>\n            <div class="stack" style="margin-top:16px">\n              <section class="panel">\n                <h2>CA Health</h2>\n                <p>Status: <span class="badge ok">{health['status']}</span></p>\n                <p>Serial: <code>{health['serial_number']}</code></p>\n                <p>Expires: {health['expires_at']} ({health['days_remaining']} hari)</p>\n                <p>Private key present: {health['private_key_present']}</p>\n              </section>\n            </div>\n            """
            return page('Dashboard Admin', body)
        civitas = get_civitas_for_user(user['id'])
        with get_connection() as conn:
            dids = conn.execute('\n                SELECT * FROM ujaja_digital_ids\n                WHERE employee_id = ?\n                ORDER BY id DESC\n                LIMIT 5\n                ', (civitas['id'],)).fetchall()
            docs = conn.execute('\n                SELECT * FROM ujaja_sign_requests\n                WHERE employee_id = ?\n                ORDER BY id DESC\n                LIMIT 5\n                ', (civitas['id'],)).fetchall()
        did_rows = ''.join((f"<tr><td>{escape(d['serial_number'] or '-')}</td><td>{escape(d['role'] or civitas['position'] or '-')}</td><td>{status_badge(d['status'])}</td><td>{escape(d['issued_at'] or '-')}</td></tr>" for d in dids)) or "<tr><td colspan='4' class='muted'>Belum ada request Digital ID.</td></tr>"
        doc_rows = ''.join((f"<tr><td>{escape(hashlib.sha256(Path(d['signed_file_path']).name.encode()).hexdigest()[:16] + '.pdf')}</td><td>{escape(d['verification_code'] or '-')}</td><td>{escape(d['signed_at'] or '-')}</td></tr>" for d in docs)) or "<tr><td colspan='3' class='muted'>Belum ada dokumen.</td></tr>"
        signature_ready = current_signature_path(user['id']) is not None
        role_label = escape(civitas['position'] or '-')
        civitas_id = escape(civitas['employee_id'] or '-')
        signature_label = 'Siap' if signature_ready else 'Belum set'
        otp_label = 'Aktif' if user['otp_enabled'] else 'Belum aktif'
        body = '\n        <div class="grid">\n          <div class="stat"><span>Role</span><b>{role_label}</b></div>\n          <div class="stat"><span>Civitas ID</span><b>{civitas_id}</b></div>\n          <div class="stat"><span>Signature</span><b>{signature_label}</b></div>\n          <div class="stat"><span>OTP</span><b>{otp_label}</b></div>\n        </div>\n        <div class="stack" style="margin-top:16px">\n          <section class="panel">\n            <h2>Alur Civitas</h2>\n            <p class="muted">Set Signature terlebih dahulu, aktifkan OTP, lalu ajukan Digital ID. Setelah Digital ID disetujui Admin CA, dokumen baru bisa ditandatangani.</p>\n          </section>\n          <section>\n            <h2>Digital ID terbaru</h2>\n            <table><thead><tr><th>Serial</th><th>Role</th><th>Status</th><th>Issued</th></tr></thead><tbody>{did_rows}</tbody></table>\n          </section>\n          <section>\n            <h2>Dokumen terbaru</h2>\n            <table><thead><tr><th>File</th><th>Kode Verifikasi Dokumen</th><th>Signed At</th></tr></thead><tbody>{doc_rows}</tbody></table>\n          </section>\n        </div>\n        '.format(role_label=role_label, civitas_id=civitas_id, signature_label=signature_label, otp_label=otp_label, did_rows=did_rows, doc_rows=doc_rows)
        return page('Dashboard Civitas', body)

    @app.route('/set-signature', methods=['GET', 'POST'])
    @require_login
    def set_signature_page():
        user = current_user()
        if is_admin_user(user):
            return redirect(url_for('dashboard'))
        civitas = get_civitas_for_user(user['id'])
        if civitas is None:
            flash('Akun ini tidak punya data civitas.')
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            try:
                save_signature_upload(request.files.get('signature'), user['id'])
                log_action(user['id'], 'SET_SIGNATURE_PROFILE', 'Signature profile civitas diperbarui.')
                flash('Signature berhasil disimpan.')
                return redirect(url_for('set_signature_page'))
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for('set_signature_page'))
        signature_path = current_signature_path(user['id'])
        if signature_path:
            version = int(signature_path.stat().st_mtime)
            preview = f'''\n            <div class="signature-preview">\n              <img src="{url_for('signature_image')}?v={version}" alt="Signature aktif">\n            </div>\n            <p class="muted">{escape(signature_path.name)}</p>\n            '''
        else:
            preview = '\n            <div class="signature-preview">\n              <div class="signature-empty">Belum ada signature kustom.</div>\n            </div>\n            '
        body = '\n        <section class="panel">\n          <h2>Set Signature</h2>\n          <div class="signature-grid">\n            <div>\n              <label>Signature aktif</label>\n              {preview}\n            </div>\n            <form method="post" enctype="multipart/form-data">\n              {csrf}\n              <div class="field">\n                <label for="signature-file">Upload foto signature</label>\n                <input id="signature-file" type="file" name="signature" accept="image/png,image/jpeg" required>\n              </div>\n              <button type="submit">Simpan Signature</button>\n            </form>\n          </div>\n        </section>\n        '.format(preview=preview, csrf=csrf_input())
        return page('Set Signature', body)

    @app.get('/signature-image')
    @require_login
    def signature_image():
        user = current_user()
        signature_path = current_signature_path(user['id'])
        if signature_path is None:
            return ('', 404)
        try:
            with Image.open(signature_path) as image:
                prepared = prepare_signature_image(image)
                output = BytesIO()
                prepared.save(output, format='PNG', optimize=True)
                output.seek(0)
                return send_file(output, mimetype='image/png')
        except Exception:
            return send_file(signature_path)

    @app.route('/request-digital-id', methods=['GET', 'POST'])
    @require_login
    @require_signature_profile
    @require_otp_enabled
    def request_digital_id_page():
        user = current_user()
        civitas = get_civitas_for_user(user['id'])
        if civitas is None:
            flash('Akun ini tidak punya data civitas.')
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            if request.form.get('passphrase', '') != request.form.get('confirm', ''):
                flash('Konfirmasi passphrase tidak cocok.')
                return redirect(url_for('request_digital_id_page'))
            try:
                request_civitas_digital_id(civitas['id'], civitas['position'], request.form.get('passphrase', ''))
                flash('Request Digital ID masuk ke antrian Admin CA.')
                return redirect(url_for('digital_id_page'))
            except ValueError as exc:
                flash(str(exc))
        body = f'''\n        <section class="panel">\n          <h2>Request Digital ID</h2>\n          <form method="post">\n            {csrf_input()}\n            <div class="field"><label>Nama</label><input value="{escape(user['name'] or '')}" disabled></div>\n            <div class="field"><label>Email</label><input value="{escape(user['email'] or '')}" disabled></div>\n            <div class="field"><label>Role</label><input value="{escape(civitas['position'] or '')}" disabled></div>\n            <div class="field"><label>Passphrase</label><input name="passphrase" type="password" minlength="8" required></div>\n            <div class="field"><label>Konfirmasi passphrase</label><input name="confirm" type="password" minlength="8" required></div>\n            <button type="submit">Request</button>\n          </form>\n        </section>\n        '''
        return page('Request Digital ID', body)

    @app.get('/digital-id')
    @require_login
    @require_signature_profile
    @require_otp_enabled
    def digital_id_page():
        user = current_user()
        civitas = get_civitas_for_user(user['id'])
        if civitas is None:
            return redirect(url_for('dashboard'))
        with get_connection() as conn:
            dids = conn.execute('\n                SELECT * FROM ujaja_digital_ids\n                WHERE employee_id = ?\n                ORDER BY id DESC\n                ', (civitas['id'],)).fetchall()
        rows = ''.join((digital_id_row(d, civitas['id']) for d in dids)) or "<tr><td colspan='7' class='muted'>Belum ada Digital ID.</td></tr>"
        body = f'''\n        <div class="actions" style="margin-bottom:14px"><a class="button" href="{url_for('download_ca')}">Download CA</a></div>\n        <table>\n          <thead><tr><th>ID</th><th>Serial</th><th>Role</th><th>Status</th><th>Issued</th><th>Expired</th><th>Download</th></tr></thead>\n          <tbody>{rows}</tbody>\n        </table>\n        '''
        return page('Digital ID Status', body)

    @app.get('/download/ca')
    @require_login
    def download_ca():
        ca = get_ujaja_ca()
        return send_file(ca['ca_file_path'], as_attachment=True, download_name='universitas_jaya_jaya_root_ca.crt')

    @app.get('/download/digital-id/<int:did_id>')
    @require_login
    @require_otp_enabled
    def download_digital_id(did_id: int):
        user = current_user()
        with get_connection() as conn:
            did = conn.execute('\n                SELECT ujaja_digital_ids.*, employees.user_id\n                FROM ujaja_digital_ids\n                JOIN employees ON employees.id = ujaja_digital_ids.employee_id\n                WHERE ujaja_digital_ids.id = ?\n                ', (did_id,)).fetchone()
        if did is None or (did['user_id'] != user['id'] and (not is_admin_user(user))):
            flash('Digital ID tidak ditemukan.')
            return redirect(url_for('digital_id_page'))
        cert_path = Path(did['certificate_file_path']) if did['certificate_file_path'] else get_ujaja_employee_signer_certificate_path(did['employee_id'])
        if not cert_path.exists() and did['certificate_pem']:
            cert_path.write_text(did['certificate_pem'], encoding='ascii')
        return send_file(cert_path, as_attachment=True, download_name=f"{did['serial_number']}.crt")

    @app.post('/download/p12/<int:did_id>')
    @require_login
    @require_otp_enabled
    def download_p12(did_id: int):
        user = current_user()
        passphrase = (request.form.get('p12_passphrase') or '').strip()
        if len(passphrase) < 8:
            flash('Passphrase .p12 minimal 8 karakter.')
            return redirect(url_for('digital_id_page'))
        with get_connection() as conn:
            did = conn.execute("\n                SELECT ujaja_digital_ids.*, employees.user_id\n                FROM ujaja_digital_ids\n                JOIN employees ON employees.id = ujaja_digital_ids.employee_id\n                WHERE ujaja_digital_ids.id = ? AND ujaja_digital_ids.status = 'Active'\n                ", (did_id,)).fetchone()
        if did is None or did['user_id'] != user['id']:
            flash('Digital ID aktif tidak ditemukan.')
            return redirect(url_for('digital_id_page'))
        p12_bytes = export_ujaja_employee_p12(did['employee_id'], passphrase)
        return send_file(BytesIO(p12_bytes), as_attachment=True, download_name=f"{did['serial_number']}.p12", mimetype='application/x-pkcs12')

    @app.route('/otp', methods=['GET', 'POST'])
    @require_login
    @require_signature_profile
    def otp_page():
        user = current_user()
        if request.method == 'POST':
            if enable_otp(user['id'], request.form.get('otp_code', '')):
                flash('OTP berhasil diaktifkan.')
                return redirect(url_for('dashboard'))
            flash('Kode OTP salah atau sudah tidak valid.')
        generate_qr_code(user['id'])
        body = f'''\n        <section class="panel">\n          <h2>Setup OTP</h2>\n          <p class="muted">Scan QR dengan aplikasi authenticator, lalu masukkan kode 6 digit dari aplikasi tersebut.</p>\n          <p><img src="{url_for('otp_qr')}" width="180" height="180" alt="OTP QR"></p>\n          <form method="post">\n            {csrf_input()}\n            <div class="field"><label>Kode OTP</label><input name="otp_code" required></div>\n            <button type="submit">Aktifkan OTP</button>\n          </form>\n        </section>\n        '''
        return page('Setup OTP', body)

    @app.get('/otp/qr')
    @require_login
    def otp_qr():
        user = current_user()
        return send_file(generate_qr_code(user['id']))

    @app.post('/pdf/placement-preview')
    @require_login
    @require_signature_profile
    @require_otp_enabled
    def pdf_placement_preview():
        try:
            return render_pdf_placement_previews(request.files.get('pdf'))
        except ValueError as exc:
            return ({'error': str(exc)}, 400)

    @app.route('/sign', methods=['GET', 'POST'])
    @require_login
    @require_signature_profile
    @require_otp_enabled
    def sign_page():
        user = current_user()
        if get_civitas_for_user(user['id']) is None:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            net_check = check_vpn_status(request, user_id=user['id'])
            if net_check.get('is_blocked'):
                flash('VPN / Proxy Detected. Please Disable VPN Before Accessing This System.')
                return redirect(url_for('sign_page'))
            upload = request.files.get('pdf')
            if not upload or not upload.filename:
                flash('Pilih PDF dulu.')
                return redirect(url_for('sign_page'))
            uploaded_path = None
            try:
                uploaded_path = save_upload(upload, 'sign')
                secure = _is_secure_request()
                result = sign_institution_pdf(get_user(user['id']), str(uploaded_path), request.form.get('otp_code', ''), signature_position_from_form(), signature_size=signature_size_from_form(), signature_page=request.form.get('signature_page', ''), is_secure=secure)
                if result.get('ssl_blocked'):
                    flash('Koneksi tidak aman (non-HTTPS). Aktifkan SSL untuk tanda tangan!')
                    return redirect(url_for('sign_page'))
                token = result.get('download_token', '')
                flash(f"PDF berhasil ditandatangani. Kode verifikasi dokumen: {result['verification_code']}")
                return redirect(url_for('download_signed', token=token))
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for('sign_page'))
            finally:
                if uploaded_path and uploaded_path.exists():
                    uploaded_path.unlink(missing_ok=True)
        signature_path = current_signature_path(user['id'])
        signature_version = int(signature_path.stat().st_mtime) if signature_path else 0
        signature_src = f"{url_for('signature_image')}?v={signature_version}"
        body = '\n        <section class="panel">\n          <h2>Sign PDF</h2>\n          <form method="post" enctype="multipart/form-data" id="sign-form">\n            __CSRF_INPUT__\n            <div class="placement-grid">\n              <div>\n                <div class="field"><label for="sign-pdf">PDF</label><input id="sign-pdf" type="file" name="pdf" accept="application/pdf" required></div>\n                <div class="placement-shell">\n                  <label>Penempatan Signature</label>\n                  <div class="pdf-scroll" id="pdf-scroll">\n                    <div class="pdf-page-card is-active" data-page-card="1">\n                      <div class="pdf-page-label">Preview PDF</div>\n                      <div class="placement-page" id="placement-page" data-page-number="1" aria-label="Area penempatan signature">\n                        <img class="pdf-preview-image" id="pdf-preview-image" alt="">\n                        <div class="pdf-preview-empty" id="pdf-preview-empty">Preview PDF</div>\n                        <div class="signature-marker" id="signature-marker" tabindex="0" role="slider" aria-label="Posisi signature">\n                          <div class="signature-preview-signature">\n                            <img class="signature-preview-cap" src="/ui/cap" alt="" draggable="false">\n                            <img class="signature-preview-autograph" src="__SIGNATURE_SRC__" alt="Signature aktif" draggable="false">\n                          </div>\n                          <div class="signature-preview-qr" aria-hidden="true"></div>\n                          <span class="signature-resize-handle" id="signature-resize-handle" aria-hidden="true"></span>\n                        </div>\n                      </div>\n                    </div>\n                  </div>\n                  <div class="placement-coords">\n                    <span>Halaman: <output id="signature-page-display">-</output></span>\n                    <span>X: <output id="position-x-display">100</output>%</span>\n                    <span>Y: <output id="position-y-display">100</output>%</span>\n                    <span>Ukuran: <output id="signature-size-display">30</output>%</span>\n                  </div>\n                </div>\n              </div>\n              <div>\n                <input type="hidden" id="position-x" name="position_x" value="100">\n                <input type="hidden" id="position-y" name="position_y" value="100">\n                <input type="hidden" id="signature-width" name="signature_width" value="30">\n                <input type="hidden" id="signature-height" name="signature_height" value="9">\n                <input type="hidden" id="signature-page" name="signature_page" value="">\n                <div class="field"><label for="sign-otp">Kode OTP</label><input id="sign-otp" name="otp_code" required></div>\n                <button type="submit">Sign with Digital ID</button>\n              </div>\n            </div>\n          </form>\n        </section>\n        <script>\n        (() => {\n          const scroll = document.getElementById("pdf-scroll");\n          const marker = document.getElementById("signature-marker");\n          const pdfInput = document.getElementById("sign-pdf");\n          const xInput = document.getElementById("position-x");\n          const yInput = document.getElementById("position-y");\n          const widthInput = document.getElementById("signature-width");\n          const heightInput = document.getElementById("signature-height");\n          const pageInput = document.getElementById("signature-page");\n          const resizeHandle = document.getElementById("signature-resize-handle");\n          const xDisplay = document.getElementById("position-x-display");\n          const yDisplay = document.getElementById("position-y-display");\n          const sizeDisplay = document.getElementById("signature-size-display");\n          const pageDisplay = document.getElementById("signature-page-display");\n          if (!scroll || !marker || !xInput || !yInput || !widthInput || !heightInput || !pageInput) return;\n\n          const clamp = (value, min, max) => Math.min(max, Math.max(min, value));\n          const stampAspect = 1763 / 892;\n          let activePage = document.getElementById("placement-page");\n\n          function bounds() {\n            if (!activePage) return { maxLeft: 0, maxTop: 0 };\n            return {\n              maxLeft: Math.max(0, activePage.clientWidth - marker.offsetWidth),\n              maxTop: Math.max(0, activePage.clientHeight - marker.offsetHeight),\n            };\n          }\n\n          function defaultHeightPercent(widthPercent) {\n            if (!activePage || !activePage.clientHeight) return 9;\n            const widthPx = activePage.clientWidth * widthPercent / 100;\n            return (widthPx / stampAspect / activePage.clientHeight) * 100;\n          }\n\n          function updateSizeInputs() {\n            if (!activePage || !activePage.clientWidth || !activePage.clientHeight) return;\n            const widthPercent = (marker.offsetWidth / activePage.clientWidth) * 100;\n            const heightPercent = (marker.offsetHeight / activePage.clientHeight) * 100;\n            widthInput.value = widthPercent.toFixed(2);\n            heightInput.value = heightPercent.toFixed(2);\n            if (sizeDisplay) sizeDisplay.value = widthPercent.toFixed(0);\n          }\n\n          function setMarkerSize(widthPercent, heightPercent) {\n            if (!activePage) return;\n            const safeWidth = clamp(Number.isFinite(widthPercent) ? widthPercent : 30, 12, 75);\n            const safeHeight = clamp(Number.isFinite(heightPercent) ? heightPercent : defaultHeightPercent(safeWidth), 4, 34);\n            marker.style.width = `${activePage.clientWidth * safeWidth / 100}px`;\n            marker.style.height = `${activePage.clientHeight * safeHeight / 100}px`;\n            updateSizeInputs();\n            setPixels(marker.offsetLeft, marker.offsetTop);\n          }\n\n          function growMarker(deltaPercent) {\n            const widthPercent = parseFloat(widthInput.value || "30") + deltaPercent;\n            setMarkerSize(widthPercent, defaultHeightPercent(widthPercent));\n          }\n\n          function setActivePage(nextPage, preservePosition = true) {\n            if (!nextPage) return;\n            const xPercent = preservePosition ? parseFloat(xInput.value || "100") : 100;\n            const yPercent = preservePosition ? parseFloat(yInput.value || "100") : 100;\n            const widthPercent = parseFloat(widthInput.value || "30");\n            const heightPercent = parseFloat(heightInput.value || "0");\n\n            activePage = nextPage;\n            scroll.querySelectorAll(".pdf-page-card").forEach((card) => card.classList.remove("is-active"));\n            activePage.closest(".pdf-page-card")?.classList.add("is-active");\n            activePage.appendChild(marker);\n\n            pageInput.value = activePage.dataset.pageNumber || "";\n            if (pageDisplay) pageDisplay.value = pageInput.value || "-";\n            requestAnimationFrame(() => {\n              setMarkerSize(widthPercent, heightPercent || defaultHeightPercent(widthPercent));\n              setPercent(xPercent, yPercent);\n            });\n          }\n\n          function setPixels(left, top) {\n            const box = bounds();\n            const nextLeft = clamp(left, 0, box.maxLeft);\n            const nextTop = clamp(top, 0, box.maxTop);\n            marker.style.left = `${nextLeft}px`;\n            marker.style.top = `${nextTop}px`;\n\n            const xPercent = box.maxLeft ? (nextLeft / box.maxLeft) * 100 : 0;\n            const yPercent = box.maxTop ? (nextTop / box.maxTop) * 100 : 0;\n            xInput.value = xPercent.toFixed(2);\n            yInput.value = yPercent.toFixed(2);\n            xDisplay.value = xPercent.toFixed(0);\n            yDisplay.value = yPercent.toFixed(0);\n            marker.setAttribute("aria-valuetext", `${xDisplay.value}%, ${yDisplay.value}%`);\n            updateSizeInputs();\n          }\n\n          function setPercent(xPercent, yPercent) {\n            const box = bounds();\n            setPixels((box.maxLeft * xPercent) / 100, (box.maxTop * yPercent) / 100);\n          }\n\n          let dragOffset = null;\n          let resizeState = null;\n          marker.addEventListener("pointerdown", (event) => {\n            if (!activePage) return;\n            if (event.target === resizeHandle) return;\n            const rect = activePage.getBoundingClientRect();\n            dragOffset = {\n              x: event.clientX - rect.left - marker.offsetLeft,\n              y: event.clientY - rect.top - marker.offsetTop,\n            };\n            marker.setPointerCapture(event.pointerId);\n            event.preventDefault();\n          });\n\n          marker.addEventListener("pointermove", (event) => {\n            if (!dragOffset) return;\n            const rect = activePage.getBoundingClientRect();\n            setPixels(event.clientX - rect.left - dragOffset.x, event.clientY - rect.top - dragOffset.y);\n          });\n\n          const releaseDrag = () => { dragOffset = null; };\n          marker.addEventListener("pointerup", releaseDrag);\n          marker.addEventListener("pointercancel", releaseDrag);\n\n          if (resizeHandle) {\n            resizeHandle.addEventListener("pointerdown", (event) => {\n              if (!activePage) return;\n              resizeState = {\n                startX: event.clientX,\n                startY: event.clientY,\n                startWidth: marker.offsetWidth,\n                startHeight: marker.offsetHeight,\n              };\n              resizeHandle.setPointerCapture(event.pointerId);\n              event.preventDefault();\n              event.stopPropagation();\n            });\n\n            resizeHandle.addEventListener("pointermove", (event) => {\n              if (!resizeState || !activePage) return;\n              const nextWidth = Math.max(\n                resizeState.startWidth + event.clientX - resizeState.startX,\n                (resizeState.startHeight + event.clientY - resizeState.startY) * stampAspect\n              );\n              const widthPercent = (nextWidth / activePage.clientWidth) * 100;\n              setMarkerSize(widthPercent, defaultHeightPercent(widthPercent));\n            });\n\n            const releaseResize = () => { resizeState = null; };\n            resizeHandle.addEventListener("pointerup", releaseResize);\n            resizeHandle.addEventListener("pointercancel", releaseResize);\n          }\n\n          scroll.addEventListener("pointerdown", (event) => {\n            const clickedPage = event.target.closest(".placement-page");\n            if (!clickedPage || event.target === marker || marker.contains(event.target)) return;\n            setActivePage(clickedPage, false);\n            const rect = activePage.getBoundingClientRect();\n            setPixels(\n              event.clientX - rect.left - marker.offsetWidth / 2,\n              event.clientY - rect.top - marker.offsetHeight / 2\n            );\n          });\n\n          marker.addEventListener("keydown", (event) => {\n            const step = event.shiftKey ? 18 : 6;\n            const currentLeft = marker.offsetLeft;\n            const currentTop = marker.offsetTop;\n            if (event.key === "ArrowLeft") setPixels(currentLeft - step, currentTop);\n            else if (event.key === "ArrowRight") setPixels(currentLeft + step, currentTop);\n            else if (event.key === "ArrowUp") setPixels(currentLeft, currentTop - step);\n            else if (event.key === "ArrowDown") setPixels(currentLeft, currentTop + step);\n            else if (event.key === "+" || event.key === "=") growMarker(2);\n            else if (event.key === "-" || event.key === "_") growMarker(-2);\n            else return;\n            event.preventDefault();\n          });\n\n          window.addEventListener("resize", () => {\n            setMarkerSize(parseFloat(widthInput.value || "30"), parseFloat(heightInput.value || "0"));\n            setPercent(parseFloat(xInput.value || "100"), parseFloat(yInput.value || "100"));\n          });\n\n          function resetPreview(label = "Preview PDF") {\n            scroll.innerHTML = "";\n            const card = document.createElement("div");\n            card.className = "pdf-page-card is-active";\n            card.dataset.pageCard = "1";\n            card.innerHTML = `\n              <div class="pdf-page-label">${label}</div>\n              <div class="placement-page" data-page-number="1" aria-label="Area penempatan signature">\n                <div class="pdf-preview-empty">${label}</div>\n              </div>\n            `;\n            scroll.appendChild(card);\n            setActivePage(card.querySelector(".placement-page"), false);\n          }\n\n          async function loadPdfPreview(file) {\n            if (!file) {\n              resetPreview();\n              return;\n            }\n            resetPreview("Memuat preview...");\n\n            const data = new FormData();\n            data.append("pdf", file);\n            data.append("_csrf_token", document.querySelector(\'meta[name="csrf-token"]\')?.content || "");\n            try {\n              const response = await fetch("/pdf/placement-preview", { method: "POST", body: data });\n              if (!response.ok) {\n                let message = "Preview gagal";\n                try {\n                  const payload = await response.json();\n                  if (payload.error) message = payload.error;\n                } catch (_error) {}\n                resetPreview(message);\n                return;\n              }\n\n              const payload = await response.json();\n              if (!payload.pages || payload.pages.length === 0) {\n                resetPreview("Preview gagal");\n                return;\n              }\n\n              scroll.innerHTML = "";\n              payload.pages.forEach((pdfPage) => {\n                const card = document.createElement("div");\n                card.className = "pdf-page-card";\n                card.dataset.pageCard = String(pdfPage.number);\n                card.innerHTML = `\n                  <div class="pdf-page-label">Halaman ${pdfPage.number}</div>\n                  <div class="placement-page has-preview" data-page-number="${pdfPage.number}" aria-label="Area penempatan signature halaman ${pdfPage.number}">\n                    <img class="pdf-preview-image" src="${pdfPage.image}" alt="">\n                  </div>\n                `;\n                const pageNode = card.querySelector(".placement-page");\n                pageNode.style.aspectRatio = `${pdfPage.width} / ${pdfPage.height}`;\n                scroll.appendChild(card);\n              });\n\n              const firstPage = scroll.querySelector(".placement-page");\n              setActivePage(firstPage, false);\n            } catch (_error) {\n              resetPreview("Preview gagal");\n            }\n          }\n\n          if (pdfInput) {\n            pdfInput.addEventListener("change", () => loadPdfPreview(pdfInput.files[0]));\n          }\n          requestAnimationFrame(() => setActivePage(activePage, false));\n        })();\n        </script>\n        '
        body = body.replace('__SIGNATURE_SRC__', signature_src).replace('__CSRF_INPUT__', csrf_input())
        return page('Sign PDF', body)

    @app.get('/sign-history')
    @require_login
    @require_otp_enabled
    def sign_history_page():
        user = current_user()
        civitas = get_civitas_for_user(user['id'])
        if civitas is None:
            return redirect(url_for('dashboard'))
        with get_connection() as conn:
            history = conn.execute('\n                SELECT ujaja_sign_requests.*\n                FROM ujaja_sign_requests\n                WHERE employee_id = ?\n                ORDER BY signed_at DESC, id DESC\n                ', (civitas['id'],)).fetchall()
        rows = ''.join((sign_history_row(item) for item in history))
        if not rows:
            rows = "<tr><td colspan='6' class='muted'>Belum ada riwayat tanda tangan.</td></tr>"
        body = f'\n        <section class="panel" style="margin-bottom:16px">\n          <h2>Sign History</h2>\n          <p class="muted">Riwayat PDF yang sudah ditandatangani oleh akun ini.</p>\n        </section>\n        <table>\n          <thead>\n            <tr>\n              <th>File</th>\n              <th>Kode Verifikasi Dokumen</th>\n              <th>Posisi</th>\n              <th>Signed At</th>\n              <th>Status</th>\n              <th>Aksi</th>\n            </tr>\n          </thead>\n          <tbody>{rows}</tbody>\n        </table>\n        '
        return page('Sign History', body)

    @app.post('/sign-history/<int:request_id>/open-pdf')
    @require_login
    @require_otp_enabled
    def open_signed_pdf(request_id: int):
        item = get_signed_request_for_user(request_id)
        if item is None:
            flash('Riwayat tanda tangan tidak ditemukan.')
            return redirect(url_for('sign_history_page'))
        path = Path(item['signed_file_path'])
        if not path.exists():
            flash('File PDF signed tidak ditemukan di folder lokal.')
            return redirect(url_for('sign_history_page'))
        try:
            open_local_path(path)
            flash(f'PDF dibuka: {path.name}')
        except Exception as exc:
            flash(f'Gagal membuka PDF: {exc}')
        return redirect(url_for('sign_history_page'))

    @app.post('/sign-history/<int:request_id>/open-folder')
    @require_login
    @require_otp_enabled
    def open_signed_folder(request_id: int):
        item = get_signed_request_for_user(request_id)
        if item is None:
            flash('Riwayat tanda tangan tidak ditemukan.')
            return redirect(url_for('sign_history_page'))
        path = Path(item['signed_file_path'])
        folder = path.parent
        if not folder.exists():
            flash('Folder PDF signed tidak ditemukan.')
            return redirect(url_for('sign_history_page'))
        try:
            open_local_path(folder)
            flash(f'Folder dibuka: {folder}')
        except Exception as exc:
            flash(f'Gagal membuka folder: {exc}')
        return redirect(url_for('sign_history_page'))

    @app.get('/download-signed/<token>')
    @require_login
    def download_signed(token: str):
        record = get_signed_request_by_token(token)
        if record is None:
            abort(404)
        user = current_user()
        if not is_admin_user(user):
            with get_connection() as conn:
                emp = conn.execute('SELECT id FROM employees WHERE user_id = ?', (user['id'],)).fetchone()
                if emp is None or emp['id'] != record['employee_id']:
                    abort(404)
        path = Path(record['signed_file_path'])
        if not path.exists():
            abort(404)
        obfuscated_name = hashlib.sha256(path.name.encode()).hexdigest()[:16] + '.pdf'
        return send_file(path, as_attachment=True, download_name=obfuscated_name)

    @app.route('/verify/<path:verification_code>', methods=['GET', 'POST'])
    def verify_code_page(verification_code: str):
        code = (verification_code or '').strip()
        with get_connection() as conn:
            record = conn.execute('\n                SELECT\n                    ujaja_sign_requests.*,\n                    employees.employee_id AS employee_code,\n                    employees.department,\n                    employees.position,\n                    users.name AS employee_name\n                FROM ujaja_sign_requests\n                JOIN employees ON employees.id = ujaja_sign_requests.employee_id\n                JOIN users ON users.id = employees.user_id\n                WHERE ujaja_sign_requests.verification_code = ?\n                ', (code,)).fetchone()
        if record is None:
            return page('Hasil Verifikasi', f"<section class='panel'><h2>Hasil Verifikasi</h2><p>Kode <code>{escape(code)}</code> tidak terdaftar.</p></section>")
        result_html = ''
        if request.method == 'POST':
            upload = request.files.get('pdf')
            if upload and upload.filename:
                uploaded_path = None
                try:
                    uploaded_path = save_upload(upload, 'verify_scan')
                    current_hash = hashlib.sha256(uploaded_path.read_bytes()).hexdigest()
                    if current_hash == record['signed_hash']:
                        try:
                            dt = datetime.fromisoformat(record['signed_at'])
                            tgl = dt.strftime('%d %B %Y')
                            jam = dt.strftime('%H:%M') + ' WIB'
                        except:
                            tgl = record['signed_at']
                            jam = '-'
                        ssl_status = 'VALID' if record.get('server_ssl_expires_at') else 'UNKNOWN'
                        result_html = f"""\n                        <div class="panel" style="border: 2px solid #10b981; padding: 20px; border-radius: 8px; background-color: #ecfdf5; margin-top: 20px; box-shadow: 0 4px 6px -1px rgba(16, 185, 129, 0.1);">\n                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px; justify-content: center;">\n                                <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>\n                                <h3 style="color: #065f46; margin: 0; font-size: 1.25rem;">VERIFIKASI DOKUMEN BERHASIL</h3>\n                            </div>\n                            <p style="text-align: center; color: #047857; margin-bottom: 20px; font-size: 15px;">PDF asli cocok dengan data tanda tangan di sistem. Dokumen utuh dan valid.</p>\n                            \n                            <div style="background: white; border-radius: 6px; padding: 16px; border: 1px solid #a7f3d0;">\n                                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">\n                                    <tr><td style="padding: 8px 0; color: #6b7280; width: 40%;">Status Validasi</td><td style="padding: 8px 0; color: #10b981; font-weight: bold; display: flex; align-items: center; gap: 6px;"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg> VALID & AUTHENTIC</td></tr>\n                                    <tr style="border-top: 1px solid #f3f4f6;"><td style="padding: 8px 0; color: #6b7280;">Signer</td><td style="padding: 8px 0; font-weight: 600; color: #111827;">{escape(record['employee_name'])}</td></tr>\n                                    <tr style="border-top: 1px solid #f3f4f6;"><td style="padding: 8px 0; color: #6b7280;">Digital ID</td><td style="padding: 8px 0; font-family: monospace; color: #374151;">{escape(record['ujaja_digital_id_serial'])}</td></tr>\n                                    <tr style="border-top: 1px solid #f3f4f6;"><td style="padding: 8px 0; color: #6b7280;">Certificate Status</td><td style="padding: 8px 0; color: #10b981; font-weight: 500;">ACTIVE</td></tr>\n                                    <tr style="border-top: 1px solid #f3f4f6;"><td style="padding: 8px 0; color: #6b7280;">Server SSL Status</td><td style="padding: 8px 0; color: #374151;">{ssl_status}</td></tr>\n                                    <tr style="border-top: 1px solid #f3f4f6;"><td style="padding: 8px 0; color: #6b7280;">Dokumen Hash</td><td style="padding: 8px 0; font-family: monospace; font-size: 12px; color: #6b7280; word-break: break-all;">{escape(record['signed_hash'])}</td></tr>\n                                    <tr style="border-top: 1px solid #f3f4f6;"><td style="padding: 8px 0; color: #6b7280;">Waktu Tanda Tangan</td><td style="padding: 8px 0; color: #374151;">{tgl} - {jam}</td></tr>\n                                    <tr style="border-top: 1px solid #f3f4f6;"><td style="padding: 8px 0; color: #6b7280;">IP Address Signer</td><td style="padding: 8px 0; color: #374151; font-family: monospace;">{escape(record.get('signer_ip_address') or 'N/A')}</td></tr>\n                                </table>\n                            </div>\n                        </div>\n                        """
                        log_action(None, 'VERIFY', f"Verifikasi SUKSES via QR Code untuk {record['verification_code']}", status='SUCCESS')
                    else:
                        result_html = f'\n                        <div class="panel" style="border: 2px solid #ef4444; padding: 20px; border-radius: 8px; background-color: #fef2f2; margin-top: 20px; box-shadow: 0 4px 6px -1px rgba(239, 68, 68, 0.1);">\n                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px; justify-content: center;">\n                                <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>\n                                <h3 style="color: #991b1b; margin: 0; font-size: 1.25rem;">DOKUMEN TIDAK VALID</h3>\n                            </div>\n                            <div style="text-align: center; color: #7f1d1d;">\n                                <p style="font-weight: bold; margin-bottom: 8px; font-size: 16px;">Isi PDF tidak sesuai dengan data sistem!</p>\n                                <p style="font-size: 14px; margin-top: 0; line-height: 1.5;">Dokumen kemungkinan telah <strong>dimodifikasi</strong>, dipalsukan, atau Anda mengunggah versi dokumen yang berbeda. Keaslian tidak dapat dijamin.</p>\n                            </div>\n                        </div>\n                        '
                        log_action(None, 'VERIFY', f"Verifikasi GAGAL via QR Code (Hash mismatch) untuk {record['verification_code']}", status='FAILED')
                finally:
                    if uploaded_path and uploaded_path.exists():
                        uploaded_path.unlink(missing_ok=True)
            else:
                flash('Pilih PDF terlebih dahulu.')
        try:
            dt = datetime.fromisoformat(record['signed_at'])
            tgl = dt.strftime('%d %B %Y')
            jam = dt.strftime('%H:%M') + ' WIB'
        except:
            tgl = record['signed_at']
            jam = '-'
        info_html = f"""\n        <div style="background: white; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; margin-bottom: 24px; box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);">\n            <div style="background-color: #f9fafb; padding: 16px 20px; border-bottom: 1px solid #e5e7eb; display: flex; align-items: center; gap: 12px;">\n                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><path d="M16 13H8"></path><path d="M16 17H8"></path><polyline points="10 9 9 9 8 9"></polyline></svg>\n                <h3 style="margin: 0; font-size: 16px; color: #111827;">Informasi Penanda Tangan</h3>\n            </div>\n            <div style="padding: 20px;">\n                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">\n                    <tr>\n                        <td style="padding: 10px 0; color: #6b7280; width: 40%; vertical-align: top;">Nama Lengkap</td>\n                        <td style="padding: 10px 0; font-weight: 600; color: #111827; vertical-align: top;">{escape(record['employee_name'])}</td>\n                    </tr>\n                    <tr style="border-top: 1px solid #f3f4f6;">\n                        <td style="padding: 10px 0; color: #6b7280; vertical-align: top;">Jabatan / Dept</td>\n                        <td style="padding: 10px 0; color: #374151; vertical-align: top;">{escape(record.get('position') or '-')} <br><span style="font-size: 12px; color: #6b7280;">{escape(record.get('department') or '-')}</span></td>\n                    </tr>\n                    <tr style="border-top: 1px solid #f3f4f6;">\n                        <td style="padding: 10px 0; color: #6b7280; vertical-align: top;">Digital ID</td>\n                        <td style="padding: 10px 0; font-family: monospace; color: #374151; vertical-align: top;">{escape(record['ujaja_digital_id_serial'])}</td>\n                    </tr>\n                    <tr style="border-top: 1px solid #f3f4f6;">\n                        <td style="padding: 10px 0; color: #6b7280; vertical-align: top;">Waktu Penandatanganan</td>\n                        <td style="padding: 10px 0; color: #374151; vertical-align: top;">{tgl}<br><span style="font-size: 12px; color: #6b7280;">{jam}</span></td>\n                    </tr>\n                </table>\n            </div>\n        </div>\n        """
        download_url = url_for('download_signed', token=record['download_token']) if record['download_token'] else '#'
        body = f'\n        <section style="max-width: 650px; margin: 0 auto; padding: 20px; font-family: system-ui, -apple-system, sans-serif;">\n          \n          <div style="text-align: center; margin-bottom: 30px;">\n            <div style="display: inline-flex; align-items: center; justify-content: center; width: 72px; height: 72px; border-radius: 50%; background-color: #dcfce7; margin-bottom: 16px; box-shadow: 0 4px 6px -1px rgba(22, 163, 74, 0.2);">\n                <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>\n            </div>\n            <h2 style="margin: 0 0 8px 0; color: #166534; font-size: 26px;">Dokumen Terdaftar</h2>\n            <p style="margin: 0; color: #4b5563; font-size: 15px;">Kode Verifikasi: <code style="background: #f3f4f6; padding: 4px 8px; border-radius: 4px; font-family: monospace; border: 1px solid #e5e7eb;">{escape(code)}</code></p>\n          </div>\n\n          {info_html}\n          \n          <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 24px; margin-bottom: 24px;">\n            <div style="display: flex; gap: 16px; margin-bottom: 16px;">\n                <div style="background-color: #dbeafe; padding: 10px; border-radius: 8px; display: flex; align-items: center; justify-content: center; align-self: flex-start;">\n                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>\n                </div>\n                <div>\n                    <h4 style="margin: 0 0 6px 0; color: #1e3a8a; font-size: 16px;">Verifikasi Keaslian Fisik / PDF</h4>\n                    <p style="margin: 0; color: #3b82f6; font-size: 14px; line-height: 1.5;">Status terdaftar di atas menandakan bahwa QR Code valid. Namun, untuk memastikan isi dokumen fisik/digital belum dimodifikasi, Anda perlu mengecek keaslian hash file PDF aslinya.</p>\n                </div>\n            </div>\n            \n            <form method="post" enctype="multipart/form-data" style="margin-top: 16px; background: white; padding: 20px; border-radius: 8px; border: 2px dashed #93c5fd; display: flex; flex-direction: column; gap: 16px; align-items: center; text-align: center;">\n                {csrf_input()}\n                <div>\n                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 8px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="12" y1="18" x2="12" y2="12"></line><line x1="9" y1="15" x2="12" y2="12"></line><line x1="15" y1="15" x2="12" y2="12"></line></svg>\n                    <p style="margin: 0 0 12px 0; font-size: 14px; color: #4b5563;">Upload file PDF dokumen asli untuk validasi hash dan signature.</p>\n                </div>\n                <input type="file" name="pdf" accept="application/pdf" required style="font-size: 14px; color: #4b5563; max-width: 100%;">\n                <button type="submit" style="background-color: #2563eb; color: white; border: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; width: 100%; max-width: 250px;">Validasi Dokumen</button>\n            </form>\n          </div>\n          \n          {result_html}\n          \n        </section>\n        '
        return page('Verifikasi Dokumen', body)

    @app.route('/verify', methods=['GET', 'POST'])
    @require_login
    def verify_page():
        result_html = ''
        if request.method == 'POST':
            upload = request.files.get('pdf')
            if upload and upload.filename:
                uploaded_path = None
                try:
                    uploaded_path = save_upload(upload, 'verify')
                    result = verify_institution_pdf(uploaded_path)
                    overall_valid = result.get('valid', False)
                    overall_badge = 'ok' if overall_valid else 'danger'
                    signatures = result.get('signatures', [])
                    sig_count = len(signatures)
                    result_html = f"""\n                    <section class="panel" style="border-left: 4px solid var({('--ok' if overall_valid else '--danger')}); margin-bottom: 18px;">\n                      <h2 style="margin-top:0;">Ringkasan Verifikasi</h2>\n                      <p style="font-size:15px;">\n                        Status Keseluruhan:\n                        <span class="badge {overall_badge}" style="font-size:13px;">\n                          {('✔ Semua Tanda Tangan Valid' if overall_valid else '✘ Ada Tanda Tangan Tidak Valid')}\n                        </span>\n                      </p>\n                      <p>Jumlah Tanda Tangan Ditemukan: <strong>{sig_count}</strong></p>\n                      <p>Keterangan: {escape(result.get('reason') or '-')}</p>\n                    </section>\n                    """
                    if signatures:

                        def _check_icon(val):
                            return '<span style="color:var(--ok);font-weight:700;">✔</span>' if val else '<span style="color:var(--danger);font-weight:700;">✘</span>'
                        for i, sig in enumerate(signatures, 1):
                            s_valid = sig.get('valid', False)
                            s_badge = 'ok' if s_valid else 'danger'
                            s_status_text = 'Valid' if s_valid else 'Tidak Valid'
                            s_reason = escape(sig.get('reason') or '-')
                            s_code = escape(sig.get('code') or '-')
                            s_name = escape(sig.get('employee_name') or '-')
                            s_email = escape(sig.get('operator_email') or '-')
                            s_dept = escape(sig.get('department') or '-')
                            s_pos = escape(sig.get('position') or '-')
                            s_inst = escape(sig.get('institution_name') or '-')
                            s_signed_at = escape(sig.get('signed_at') or '-')
                            s_ca_serial = escape(sig.get('ca_serial') or '-')
                            s_did_serial = escape(sig.get('digital_id_serial') or '-')
                            hash_ok = sig.get('hash_match', False)
                            ca_ok = sig.get('ca_match', False)
                            did_ok = sig.get('digital_id_match', False)
                            sig_ok = sig.get('signature_valid', False)
                            result_html += f"""\n                            <section class="panel" style="border-left: 4px solid var({('--ok' if s_valid else '--danger')}); margin-bottom: 14px;">\n                              <h3 style="margin-top:0; display:flex; align-items:center; gap:8px;">\n                                Tanda Tangan #{i}\n                                <span class="badge {s_badge}" style="font-size:12px;">{s_status_text}</span>\n                              </h3>\n                              <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 6px 24px; font-size:14px;">\n                                <div><strong>Nama Penanda Tangan:</strong> {s_name}</div>\n                                <div><strong>Email:</strong> {s_email}</div>\n                                <div><strong>Jabatan:</strong> {s_pos}</div>\n                                <div><strong>Departemen:</strong> {s_dept}</div>\n                                <div><strong>Institusi:</strong> {s_inst}</div>\n                                <div><strong>Waktu Tanda Tangan:</strong> {s_signed_at}</div>\n                                <div><strong>Kode Verifikasi:</strong> <code style="background:var(--surface);padding:2px 6px;border-radius:4px;">{s_code}</code></div>\n                                <div><strong>Keterangan:</strong> {s_reason}</div>\n                              </div>\n                              <hr style="border:none; border-top:1px solid var(--line); margin:10px 0 8px;">\n                              <div style="display:flex; gap:18px; flex-wrap:wrap; font-size:13px;">\n                                <span>{_check_icon(hash_ok)} Integritas Hash</span>\n                                <span>{_check_icon(ca_ok)} CA Match</span>\n                                <span>{_check_icon(did_ok)} Digital ID</span>\n                                <span>{_check_icon(sig_ok)} Signature</span>\n                              </div>\n                              <div style="margin-top:8px; font-size:12px; color:var(--muted);">\n                                CA Serial: {s_ca_serial} &nbsp;|&nbsp; Digital ID Serial: {s_did_serial}\n                              </div>\n                            </section>\n                            """
                    elif not overall_valid:
                        result_html += f"""\n                        <section class="panel" style="border-left: 4px solid var(--danger); margin-bottom: 14px;">\n                          <p><strong>Kode Verifikasi:</strong> <code>{escape(result.get('code') or '-')}</code></p>\n                          <p><strong>Keterangan:</strong> {escape(result.get('reason') or '-')}</p>\n                        </section>\n                        """
                finally:
                    if uploaded_path and uploaded_path.exists():
                        uploaded_path.unlink(missing_ok=True)
            else:
                flash('Pilih PDF dulu.')
        body = f'\n        <section class="panel">\n          <h2>Verify PDF</h2>\n          <form method="post" enctype="multipart/form-data">\n            {csrf_input()}\n            <div class="field"><label>PDF</label><input type="file" name="pdf" accept="application/pdf" required></div>\n            <button type="submit">Verify</button>\n          </form>\n        </section>\n        <div style="height:16px"></div>\n        {result_html}\n        '
        return page('Verify PDF', body)

    @app.get('/admin/requests')
    @require_admin
    def admin_requests():
        with get_connection() as conn:
            requests = conn.execute("\n                SELECT ujaja_digital_ids.*, employees.employee_id AS emp_code, employees.department\n                FROM ujaja_digital_ids\n                JOIN employees ON employees.id = ujaja_digital_ids.employee_id\n                WHERE ujaja_digital_ids.status = 'Pending'\n                ORDER BY ujaja_digital_ids.id ASC\n                ").fetchall()
        rows = ''.join((request_row(r) for r in requests)) or "<tr><td colspan='6' class='muted'>Tidak ada pending request.</td></tr>"
        body = f'\n        <table><thead><tr><th>NIP/NIM</th><th>Nama</th><th>Unit</th><th>Role</th><th>Serial Request</th><th>Aksi</th></tr></thead><tbody>{rows}</tbody></table>\n        '
        return page('Digital ID Requests', body)

    @app.post('/admin/requests/<int:request_id>/approve')
    @require_admin
    @require_otp_enabled
    def approve_request(request_id: int):
        try:
            approve_civitas_digital_id_request(request_id, current_user()['id'])
            flash('Digital ID disetujui dan diterbitkan.')
        except ValueError as exc:
            flash(str(exc))
        return redirect(url_for('admin_requests'))

    @app.post('/admin/requests/<int:request_id>/reject')
    @require_admin
    @require_otp_enabled
    def reject_request(request_id: int):
        try:
            reject_civitas_digital_id_request(request_id, request.form.get('reason', ''), current_user()['id'])
            flash('Request ditolak.')
        except ValueError as exc:
            flash(str(exc))
        return redirect(url_for('admin_requests'))

    @app.get('/admin/certificates')
    @require_admin
    def admin_certificates():
        with get_connection() as conn:
            certs = conn.execute("\n                SELECT ujaja_digital_ids.*, employees.employee_id AS emp_code\n                FROM ujaja_digital_ids\n                JOIN employees ON employees.id = ujaja_digital_ids.employee_id\n                WHERE ujaja_digital_ids.status IN ('Active', 'Superseded', 'Revoked')\n                ORDER BY ujaja_digital_ids.id DESC\n                ").fetchall()
        rows = ''.join((certificate_row(c) for c in certs)) or "<tr><td colspan='7' class='muted'>Belum ada sertifikat.</td></tr>"
        body = f'\n        <table><thead><tr><th>Nama</th><th>NIP/NIM</th><th>Serial</th><th>Status</th><th>Issued</th><th>Expired</th><th>Aksi</th></tr></thead><tbody>{rows}</tbody></table>\n        '
        return page('Certificates', body)

    @app.post('/admin/certificates/<int:did_id>/revoke')
    @require_admin
    @require_otp_enabled
    def revoke_certificate(did_id: int):
        reason = (request.form.get('reason') or '').strip()
        if not reason:
            flash('Alasan revoke wajib diisi.')
            return redirect(url_for('admin_certificates'))
        with get_connection() as conn:
            cert = conn.execute('SELECT * FROM ujaja_digital_ids WHERE id = ?', (did_id,)).fetchone()
            if cert:
                conn.execute("\n                    UPDATE ujaja_digital_ids\n                    SET status = 'Revoked',\n                        is_revoked = 1,\n                        revoked_at = CURRENT_TIMESTAMP\n                    WHERE id = ?\n                    ", (did_id,))
        log_action(current_user()['id'], 'REVOKE_DIGITAL_ID', f'Sertifikat {did_id} direvoke. Alasan: {reason}')
        flash('Sertifikat direvoke.')
        return redirect(url_for('admin_certificates'))

    @app.get('/admin/audit')
    @require_admin
    def admin_audit():
        rows = ''.join((f"<tr><td>{escape(log['created_at'] or '-')}</td><td>{escape(log['user_email'] or '-')}</td><td>{escape(log['action'] or '-')}</td><td>{escape(log['description'] or '-')}</td></tr>" for log in list_recent_logs(150))) or "<tr><td colspan='4' class='muted'>Belum ada audit log.</td></tr>"
        body = f'\n        <table><thead><tr><th>Waktu</th><th>User</th><th>Action</th><th>Deskripsi</th></tr></thead><tbody>{rows}</tbody></table>\n        '
        return page('Audit Logs', body)
    return app

def status_badge(status: str) -> str:
    labels = {'Active': 'Aktif', 'Pending': 'Menunggu', 'Rejected': 'Ditolak', 'Revoked': 'Dicabut', 'Superseded': 'Digantikan'}
    cls = 'ok' if status == 'Active' else 'danger' if status in ('Revoked', 'Rejected') else 'warn'
    return f"<span class='badge {cls}'>{escape(labels.get(status, status or '-'))}</span>"

def display_signature_position(position: str | None) -> str:
    if not position:
        return '-'
    if position.startswith('page '):
        page_label, _separator, custom_position = position.partition(':')
        normalized_page = page_label.replace('page ', 'Halaman ', 1)
        return normalized_page if custom_position.startswith('custom:') else position
    if position.startswith('custom:'):
        return 'Custom'
    return position

def sign_history_row(item) -> str:
    signed_path_value = item['signed_file_path'] or ''
    signed_path = Path(signed_path_value) if signed_path_value else None
    file_exists = bool(signed_path and signed_path.exists())
    folder_exists = bool(signed_path and signed_path.parent.exists())
    pdf_disabled = 'disabled' if not file_exists else ''
    folder_disabled = 'disabled' if not folder_exists else ''
    status_class = 'ok' if item['status'] == 'Signed' and file_exists else 'warn'
    status_text = item['status'] or '-'
    if not file_exists:
        status_text = 'File tidak ditemukan'
    token = item['download_token'] or ''
    display_name = hashlib.sha256((signed_path.name if signed_path else '').encode()).hexdigest()[:16] + '.pdf' if signed_path else '-'
    return f"""\n    <tr>\n      <td>{escape(display_name)}</td>\n      <td><code>{escape(item['verification_code'] or '-')}</code></td>\n      <td>{escape(display_signature_position(item['signature_position']))}</td>\n      <td>{escape(item['signed_at'] or '-')}</td>\n      <td><span class="badge {status_class}">{escape(status_text)}</span></td>\n      <td>\n        <div class="actions">\n          <form method="post" action="/sign-history/{item['id']}/open-pdf">\n            {csrf_input()}\n            <button type="submit" {pdf_disabled}>Open PDF</button>\n          </form>\n          <form method="post" action="/sign-history/{item['id']}/open-folder">\n            {csrf_input()}\n            <button type="submit" {folder_disabled}>Open Folder</button>\n          </form>\n        </div>\n      </td>\n    </tr>\n    """

def digital_id_row(did, employee_id: int) -> str:
    downloads = ''
    if did['status'] in ('Active', 'Superseded') and did['certificate_pem']:
        downloads = f"<a href='/download/digital-id/{int(did['id'])}'>.crt</a>"
    if did['status'] == 'Active':
        downloads += f"""\n        <form method="post" action="/download/p12/{int(did['id'])}" class="actions" style="margin-top:8px">\n          {csrf_input()}\n          <input name="p12_passphrase" type="password" placeholder="Passphrase .p12" minlength="8" required style="max-width:170px">\n          <button type="submit">.p12</button>\n        </form>\n        """
    return f"<tr><td>{int(did['id'])}</td><td><code>{escape(did['serial_number'] or '-')}</code></td><td>{escape(did['role'] or '-')}</td><td>{status_badge(did['status'])}</td><td>{escape(did['issued_at'] or '-')}</td><td>{escape(did['expired_at'] or '-')}</td><td>{downloads or '-'}</td></tr>"

def request_row(req) -> str:
    return f"""\n    <tr>\n      <td>{escape(req['emp_code'] or '-')}</td>\n      <td>{escape(req['digital_id_name'] or '-')}</td>\n      <td>{escape(req['department'] or '-')}</td>\n      <td>{escape(req['role'] or '-')}</td>\n      <td><code>{escape(req['serial_number'] or '-')}</code></td>\n      <td>\n        <div class="actions">\n          <form method="post" action="/admin/requests/{int(req['id'])}/approve">{csrf_input()}<button type="submit">Setujui</button></form>\n          <form method="post" action="/admin/requests/{int(req['id'])}/reject">\n            {csrf_input()}\n            <input name="reason" placeholder="Alasan reject" required style="max-width:170px">\n            <button class="danger" type="submit">Tolak</button>\n          </form>\n        </div>\n      </td>\n    </tr>\n    """

def certificate_row(cert) -> str:
    action = '-'
    if cert['status'] == 'Active':
        action = f"""\n        <form method="post" action="/admin/certificates/{int(cert['id'])}/revoke" class="actions">\n          {csrf_input()}\n          <input name="reason" placeholder="Alasan revoke" required style="max-width:170px">\n          <button class="danger" type="submit">Revoke</button>\n        </form>\n        """
    return f"\n    <tr>\n      <td>{escape(cert['digital_id_name'] or '-')}</td>\n      <td>{escape(cert['emp_code'] or '-')}</td>\n      <td><code>{escape(cert['serial_number'] or '-')}</code></td>\n      <td>{status_badge(cert['status'])}</td>\n      <td>{escape(cert['issued_at'] or '-')}</td>\n      <td>{escape(cert['expired_at'] or '-')}</td>\n      <td>{action}</td>\n    </tr>\n    "
app = create_app()