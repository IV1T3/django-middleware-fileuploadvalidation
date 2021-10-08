# from django_fileuploadvalidation.data import whitelists

from django.conf import settings

UPLOAD_CONFIGURATION = getattr(
    settings,
    "UPLOAD_CONFIGURATION",
    {},
)
