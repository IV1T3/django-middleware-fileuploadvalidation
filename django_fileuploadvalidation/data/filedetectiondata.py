FILE_DETECTION_DATA_TEMPLATE = {
    "file": {
        "extensions": {"main": [""], "other": [""]},
        "guessed_mime": "",
        "malicious": True,
        "request_header_mime": "",
        "signature_mime": "",
        "size": "",
    },
    "checks_done": {
        "extension_signature_request_mime_match": False,
        "signature_valid": False,
        "whitelisted_extensions_mime": False,
        "whitelisted_request_mime": False,
        "whitelisted_signature_mime": False,
    },
    "recognized_attacks": {
        "additional_file_extensions": False,
        "exif_injection": False,
        "mime_manipulation": False,
        "null_byte_injection": False,
    },
    "sanitization_tasks": {
        "start_sanitization": True,
        "clean_exif": False,
        "clean_structure": False,
        "create_random_filename_with_guessed_extension": True,
    },
}