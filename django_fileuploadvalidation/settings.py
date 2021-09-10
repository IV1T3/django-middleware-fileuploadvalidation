from .data import whitelists

from django.conf import settings

DETECTOR_SENSITIVITY = getattr(settings, 'DETECTOR_SENSITIVITY', 0.99)
UPLOAD_MIME_TYPE_WHITELIST = getattr(settings, 'UPLOAD_MIME_TYPE_WHITELIST', whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE)
UPLOADLOGS_MODE = getattr(settings, 'UPLOADLOGS_MODE', 'blocked')
FILE_SIZE_LIMIT = getattr(settings, 'FILE_SIZE_LIMIT', 5000)
FILENAME_LENGTH_LIMIT = getattr(settings, 'FILENAME_LENGTH_LIMIT', 100)