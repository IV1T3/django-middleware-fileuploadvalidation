import logging

from . import basic, image


def sanitize(files, upload_config):
    logging.debug("[Sanitizer module] - Starting sanitization")

    sanitized_files = {}

    for file_name, file in files.items():

        # Perform basic file sanitization
        file = basic.sanitize_file(file, upload_config)

        # Get guessed file type
        file_type = file.detection_results.guessed_mime

        # Perform file type specific sanitization
        if file_type.startswith("application"):
            pass
        elif file_type.startswith("audio"):
            pass
        elif file_type.startswith("image"):
            file = image.sanitize_file(file)
        elif file_type.startswith("text"):
            pass
        elif file_type.startswith("video"):
            pass
        else:
            file = image.sanitize_file(file)

        sanitized_files[file_name] = file

    return sanitized_files
