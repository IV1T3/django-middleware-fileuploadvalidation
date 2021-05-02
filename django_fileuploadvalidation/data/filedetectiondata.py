FILE_DETECTION_DATA_TEMPLATE = {
    "file": {
        "block": False,
        "block_reasons": [],
        "extensions": [],
        "guessed_mime": "",
        "malicious": True,
        "request_header_mime": "",
        "signature_mime": "",
        "size": "",
    },
    "checks": {
        "validation_filename_length": {
            "done": False,
            "result": False,
        },
        "validation_match_extension_signature_request_mime": {
            "done": False,
            "result": False,
        },
        "validation_file_size": {"done": False, "result": False},
        "validation_signature": {"done": False, "result": False},
        "whitelisted_extensions_mime": {"done": False, "result": False},
        "whitelisted_request_mime": {"done": False, "result": False},
        "whitelisted_signature_mime": {"done": False, "result": False},
    },
    "recognized_attacks": {
        "additional_file_extensions": False,
        "exif_injection": False,
        "file_size_large": False,
        "mime_manipulation": False,
        "null_byte_injection": False,
    },
    "sanitization_tasks": {
        "clean_exif": False,
        "clean_structure": True,
        "create_random_filename_with_guessed_extension": True,
        "start_sanitization": True,
    },
}