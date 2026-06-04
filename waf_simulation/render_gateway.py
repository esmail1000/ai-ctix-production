import os
import threading

from defense_suite_master import app, run_pdf_watcher


def main():
    port = int(os.environ.get("PORT", os.environ.get("WAF_PORT", "10000")))

    watcher_thread = threading.Thread(target=run_pdf_watcher, daemon=True)
    watcher_thread.start()

    print(f"[WAF Gateway] Listening publicly on 0.0.0.0:{port}")
    print("[WAF Gateway] Forwarding clean traffic to http://127.0.0.1:3000")

    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()