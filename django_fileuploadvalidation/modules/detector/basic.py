import logging

from ...data.filesignatures import FILE_SIGNATURES


def match_file_signature(file_object):
    logging.info("[Detector module] - Matching file signature")

    for mime_type in FILE_SIGNATURES:
        mime_dict = FILE_SIGNATURES[mime_type]
        file_content = file_object.content
        if file_content.startswith(mime_dict["start"]):
            for full_signature_key in mime_dict["full_signatures"]:
                current_signature_dict = mime_dict["full_signatures"][
                    full_signature_key
                ]
                correct_signature = current_signature_dict["signature"]
                correct_signature_length = current_signature_dict["signature_length"]
                matching_signature = file_content[:correct_signature_length]
                if correct_signature == matching_signature:
                    logging.debug(
                        f"[Detector module - Basic] - Signature found: {matching_signature}"
                    )
                    return mime_type

    logging.debug("[Detector module - Basic] - Signature unknown")
    return "__unknown"


def get_filename_splits(file_object):
    file_name_splits = list(
        map(lambda x: x.lower(), file_object.basic_information.name.split("."))
    )

    return file_name_splits


def detect_file(file):
    logging.info("[Detector module] - Starting basic detection")

    filename_splits = get_filename_splits(file)
    file.detection_results.filename_splits = filename_splits

    file.detection_results.extensions = filename_splits[1:]

    file.detection_results.signature_mime = match_file_signature(file)

    return file
