from .data import whitelists

"""
    DETECTOR_SENSITIVITY
    Threshold from which the detector module denotes file as malicious.
    The higher the sensitivity the more strict the detector module.
    ---
    Type: float
    Default: 0.98
"""
DETECTOR_SENSITIVITY = 0.98


"""
    UPLOAD_MIME_TYPE_WHITELIST
    Select the upload whitelist.
    This will only allow certain MIME types to be uploaded.

    Possible whitelists
    -------------------
    - whitelists.WHITELIST_MIME_TYPES__AUDIO_ALL
    - whitelists.WHITELIST_MIME_TYPES__APPLICATION_ALL
    - whitelists.WHITELIST_MIME_TYPES__IMAGE_ALL
    - whitelists.WHITELIST_MIME_TYPES__TEXT_ALL
    - whitelists.WHITELIST_MIME_TYPES__VIDEO_ALL

    - whitelists.WHITELIST_MIME_TYPES__AUDIO_RESTRICTIVE
    - whitelists.WHITELIST_MIME_TYPES__APPLICATION_RESTRICTIVE
    - whitelists.WHITELIST_MIME_TYPES__IMAGE_RESTRICTIVE
    - whitelists.WHITELIST_MIME_TYPES__TEXT_RESTRICTIVE
    - whitelists.WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE

    - whitelists.WHITELIST_MIME_TYPES__ALL
    - whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE
    ---
    Type: list
    Default: whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE
"""
UPLOAD_MIME_TYPE_WHITELIST = whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE

"""
    UPLOADLOGS_MODE
    always: Log every upload attempt.
    success: Log only successful uploads.
    blocked: Log only blocked uploads.
    ---
    Type: str
    Default: "blocked"
"""
UPLOADLOGS_MODE = "blocked"

"""
    FILE_SIZE_LIMIT
    Defines the maximum allowed file size in kilobytes (kB).
    ---
    Type: integer
    Default: 5000
"""
FILE_SIZE_LIMIT = 5000

"""
    FILENAME_LENGTH_LIMIT
    Defines the maximum allowed character length of the file name.
    ---
    Type: integer
    Default: 100
"""
FILENAME_LENGTH_LIMIT = 100