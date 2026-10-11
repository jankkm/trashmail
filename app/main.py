"""Entry point: web UI (uvicorn) + SMTP server (started in the app lifespan)."""
import logging

import uvicorn

from . import config
from .web.app import create_app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    boot = config.boot()
    uvicorn.run(create_app(), host=boot.web_host, port=boot.web_port, log_level="info")


if __name__ == "__main__":
    main()
