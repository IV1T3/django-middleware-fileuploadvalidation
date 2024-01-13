import mimetypes

mimetypes.init()
all_mimetypes = list(mimetypes.types_map.values())

WHITELIST_MIME_TYPES__AUDIO_ALL = [
    mimetype for mimetype in all_mimetypes if mimetype.startswith("audio/")
]
WHITELIST_MIME_TYPES__APPLICATION_ALL = [
    mimetype for mimetype in all_mimetypes if mimetype.startswith("application/")
]
WHITELIST_MIME_TYPES__IMAGE_ALL = [
    mimetype for mimetype in all_mimetypes if mimetype.startswith("image/")
]
WHITELIST_MIME_TYPES__TEXT_ALL = [
    mimetype for mimetype in all_mimetypes if mimetype.startswith("text/")
]
WHITELIST_MIME_TYPES__VIDEO_ALL = [
    mimetype for mimetype in all_mimetypes if mimetype.startswith("video/")
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
WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE = ["video/mp4", "video/mpeg", "video/quicktime"]

WHITELIST_MIME_TYPES__ALL = all_mimetypes
WHITELIST_MIME_TYPES__RESTRICTIVE = (
    WHITELIST_MIME_TYPES__AUDIO_RESTRICTIVE
    + WHITELIST_MIME_TYPES__APPLICATION_RESTRICTIVE
    + WHITELIST_MIME_TYPES__IMAGE_RESTRICTIVE
    + WHITELIST_MIME_TYPES__TEXT_RESTRICTIVE
    + WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE
)
