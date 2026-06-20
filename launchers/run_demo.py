import sys
sys.dont_write_bytecode = True
from web_runtime.web_app import create_app

def main() -> None:
    app = create_app()
    if None in app.before_request_funcs:
        app.before_request_funcs[None] = [f for f in app.before_request_funcs[None] if f.__name__ != 'enforce_https']
    print('=' * 60)
    print('MODE DEMO INSECURE (TANPA SSL / HTTP)')
    print('Silakan buka URL berikut di browser:')
    print('http://127.0.0.1:5050')
    print('=' * 60)
    app.run(host='127.0.0.1', port=5050, debug=False)
if __name__ == '__main__':
    main()