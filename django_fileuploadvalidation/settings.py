# from django_fileuploadvalidation.data import whitelists

from django.conf import settings

UPLOAD_CONFIGURATION = getattr(
    settings,
    "UPLOAD_CONFIGURATION",
    {
        "default": {
            "clamav": False,
            "file_size_limit": 500000000,
            "filename_length_limit": 100,
            "sanitization": True,
            "sensitivity": 0.99,
            "uploadlogs_mode": "blocked",
            "whitelist": "RESTRICTIVE",
            "whitelist_custom": [],
        },
    },
)
