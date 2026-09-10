import logging
import os
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

logger = logging.getLogger('certificate_tool')
logger.addHandler(logging.NullHandler())


def configure_logging():
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler):
            return Path(handler.baseFilename)
    root = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent
    for directory in (root / 'logs', Path(tempfile.gettempdir()) / 'certificate_tool_logs'):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / 'certificate_tool.log'
            handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            return path
        except OSError:
            continue
    return None
