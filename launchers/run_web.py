import sys
sys.dont_write_bytecode = True
from web_runtime.web_app import create_app
from web_runtime.web_ssl import ensure_localhost_certificate

def main() -> None:
    cert_file, key_file = ensure_localhost_certificate()
    ssl_context = (str(cert_file), str(key_file))
    app = create_app()
    print(f'Ujaja Sign web app: https://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, ssl_context=ssl_context, debug=False)
if __name__ == '__main__':
    main()