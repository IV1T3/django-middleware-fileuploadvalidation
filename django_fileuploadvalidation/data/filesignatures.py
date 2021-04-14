FILE_SIGNATURES = {
    "image/gif": {
        "start": b"\x47\x49\x46",
        "full_signatures": {
            "0": {
                "signature": b"\x47\x49\x46\x38\x37\x61",
                "signature_length": 6,
            },
            "1": {
                "signature": b"\x47\x49\x46\x38\x39\x61",
                "signature_length": 6,
            },
        },
    },
    "image/jpeg": {
        "start": b"\xFF\xD8\xFF",
        "full_signatures": {
            "0": {
                "signature": b"\xFF\xD8\xFF\xDB",
                "signature_length": 4,
            },
            "1": {
                "signature": b"\xFF\xD8\xFF\xEE",
                "signature_length": 4,
            },
            "2": {
                "signature": b"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01",
                "signature_length": 12,
            },
            "3": {
                "signature": b"\xFF\xD8\xFF\xE1\x00\x18\x45\x78\x69\x66\x00\x00",
                "signature_length": 12,
            },
        },
    },
    "audio/mpeg": {
        "start": b"\xFF",
        "full_signatures": {
            "0": {
                "signature": b"\xFF\xFB",
                "signature_length": 2,
            },
            "1": {
                "signature": b"\xFF\xF3",
                "signature_length": 2,
            },
            "2": {
                "signature": b"\xFF\xF2",
                "signature_length": 2,
            },
            "3": {
                "signature": b"\x49\x44\x33",
                "signature_length": 3,
            },
        },
    },
    "video/mp4": {
        "start": b"\x00\x00\x00\x18\x66",
        "full_signatures": {
            "0": {
                "signature": b"\x00\x00\x00\x18\x66\x74\x79\x70\x69\x73\x6F\x6D",
                "signature_length": 12,
            }
        },
    },
    "application/pdf": {
        "start": b"\x25\x50\x44",
        "full_signatures": {
            "0": {
                "signature": b"\x25\x50\x44\x46\x2D",
                "signature_length": 5,
            }
        },
    },
    "image/png": {
        "start": b"\x89\x50\x4E",
        "full_signatures": {
            "0": {
                "signature": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
                "signature_length": 8,
            }
        },
    },
    "application/rtf": {
        "start": b"\x7B\x5C\x72",
        "full_signatures": {
            "0": {
                "signature": b"\x7B\x5C\x72\x74\x66\x31",
                "signature_length": 6,
            }
        },
    },
    "image/tiff": {
        "start": b"",
        "full_signatures": {
            "0": {
                "signature": b"\x49\x49\x2A\x00",
                "signature_length": 4,
            },
            "1": {
                "signature": b"\x4D\x4D\x00\x2A",
                "signature_length": 4,
            },
        },
    },
}