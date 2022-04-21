import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
version_info = json.loads(BASE_DIR.joinpath('django_rest_crypto', 'version.json').read_text())
