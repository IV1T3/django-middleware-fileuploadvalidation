from .mimetypes import MIME_TYPES

WHITELIST_MIME_TYPES__AUDIO_ALL = [
    mime_type_key for mime_type_key in MIME_TYPES if mime_type_key.startswith("audio/")
]
WHITELIST_MIME_TYPES__APPLICATION_ALL = [
    mime_type_key
    for mime_type_key in MIME_TYPES
    if mime_type_key.startswith("application/")
]
WHITELIST_MIME_TYPES__IMAGE_ALL = [
    mime_type_key for mime_type_key in MIME_TYPES if mime_type_key.startswith("image/")
]
WHITELIST_MIME_TYPES__TEXT_ALL = [
    mime_type_key for mime_type_key in MIME_TYPES if mime_type_key.startswith("text/")
]
WHITELIST_MIME_TYPES__VIDEO_ALL = [
    mime_type_key for mime_type_key in MIME_TYPES if mime_type_key.startswith("video/")
]

WHITELIST_MIME_TYPES__AUDIO_RESTRICTIVE = ["audio/mpeg"]
WHITELIST_MIME_TYPES__APPLICATION_RESTRICTIVE = ["application/pdf"]
WHITELIST_MIME_TYPES__IMAGE_RESTRICTIVE = [
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/tiff",
]
WHITELIST_MIME_TYPES__TEXT_RESTRICTIVE = ["text/plain"]
WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE = ["video/mp4", "video/mpeg"]

WHITELIST_MIME_TYPES__ALL = [mime_type_key for mime_type_key in MIME_TYPES]
WHITELIST_MIME_TYPES__RESTRICTIVE = (
    WHITELIST_MIME_TYPES__AUDIO_RESTRICTIVE
    + WHITELIST_MIME_TYPES__APPLICATION_RESTRICTIVE
    + WHITELIST_MIME_TYPES__IMAGE_RESTRICTIVE
    + WHITELIST_MIME_TYPES__TEXT_RESTRICTIVE
    + WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE
)
