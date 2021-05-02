import copy
import logging
import operator
import pprint

from ..config import (
    DETECTOR_SENSITIVITY,
    UPLOAD_MIME_TYPE_WHITELIST,
    FILE_SIZE_LIMIT,
    FILENAME_LENGTH_LIMIT
)

from ..data.filedetectiondata import FILE_DETECTION_DATA_TEMPLATE
from ..data.filesignatures import FILE_SIGNATURES
from ..data.mimetypes import MIME_TYPES

from .helper import file_extension_to_mime_type


def get_file_size(file_object, detection_data):
    logging.info("[Detector module] - Getting file size")
    detection_data["file"]["size"] = file_object.size
    return detection_data


def check_file_size_allowed(detection_data):
    file_size = detection_data["file"]["size"] / 1000
    if file_size <= FILE_SIZE_LIMIT:
        detection_data["checks"]["validation_file_size"]["result"] = True
    else:
        detection_data["checks"]["validation_file_size"]["result"] = False
        detection_data["recognized_attacks"]["file_size_large"] = True
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("invalid_file_size")

    detection_data["checks"]["validation_file_size"]["done"] = True

    return detection_data


def check_mime_against_whitelist(mime_to_check):
    return mime_to_check in UPLOAD_MIME_TYPE_WHITELIST


def get_request_header_mime(file_object, detection_data):
    logging.info("[Detector module] - Getting request header MIME type")

    detection_data["file"]["request_header_mime"] = file_object.content_type

    mime_whitelist_result = check_mime_against_whitelist(file_object.content_type)

    detection_data["checks"]["whitelisted_request_mime"]["done"] = True
    detection_data["checks"]["whitelisted_request_mime"][
        "result"
    ] = mime_whitelist_result

    if not mime_whitelist_result:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("whitelist_content_type")

    return detection_data


def check_file_exif_data(file_object, detection_data):
    logging.info("[Detector module] - Getting exif data")
    exif_data = file_object.exif_data
    # logging.debug(f"[Detector module] - {exif_data=}")
    # TODO: Add detection of exif injection
    malicious_injections = ["<?", "<script>"]

    if len(exif_data) > 0:
        detection_data["sanitization_tasks"]["clean_exif"] = True

    return detection_data


def check_filename(file_object, detection_data):
    logging.info("[Detector module] - Analyzing file extension")

    # Validating file name length
    if len(file_object.name) < FILENAME_LENGTH_LIMIT:
        detection_data["checks"]["validation_filename_length"]["result"] = True
    else:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("validation_filename_length")

    detection_data["checks"]["validation_filename_length"]["done"] = True


    file_name_splits = list(map(lambda x: x.lower(), file_object.name.split(".")))

    # TODO: change from static to dynamic detection of main extension
    # Could result in detecting files as malicious if
    # "." in the file name

    file_extensions = file_name_splits[1:]
    detection_data["file"]["extensions"] = file_extensions
    mime_whitelist_results = []
    for single_extension in file_extensions:
        curr_file_extension_mime = file_extension_to_mime_type(single_extension)
        mime_whitelist_results.append(check_mime_against_whitelist(curr_file_extension_mime))

    all_extensions_whitelisted = all(mime_whitelist_results)

    detection_data["checks"]["whitelisted_extensions_mime"]["done"] = True
    detection_data["checks"]["whitelisted_extensions_mime"]["result"] = all_extensions_whitelisted
    
    if len(file_name_splits) > 2:
        detection_data["recognized_attacks"]["additional_file_extensions"] = True

    if not all_extensions_whitelisted:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("whitelist_file_extension")

    for file_name_split in file_name_splits:
        if (
            "0x00" in file_name_split
            or "%00" in file_name_split
            or "\0" in file_name_split
        ):
            detection_data["recognized_attacks"]["null_byte_injection"] = True

    # TODO: Add detection of alternate media file extensions such as .php5

    return detection_data


def check_signature_match_main_file_extension(detection_data):

    file_request_mime = detection_data["file"]["request_header_mime"]
    file_signature_mime = detection_data["file"]["signature_mime"]

    extension_matchings = []

    for single_file_extension in detection_data["file"]["extensions"]:
        file_extension_mime = file_extension_to_mime_type(single_file_extension)
        extension_matches = file_extension_mime == file_signature_mime == file_request_mime
        extension_matchings.append(extension_matches)
    
    all_extensions_match = all(extension_matchings)

    if all_extensions_match:
        detection_data["checks"]["validation_match_extension_signature_request_mime"][
            "result"
        ] = True
    else:
        detection_data["recognized_attacks"]["mime_manipulation"] = True
        detection_data["checks"]["validation_match_extension_signature_request_mime"][
            "result"
        ] = False

    detection_data["checks"]["validation_match_extension_signature_request_mime"][
        "done"
    ] = True
    return detection_data


def match_file_signature(file_content):
    logging.info("[Detector module] - Matching file signature")

    for mime_type in FILE_SIGNATURES:
        mime_dict = FILE_SIGNATURES[mime_type]
        if file_content.startswith(mime_dict["start"]):
            for full_signature_key in mime_dict["full_signatures"]:
                current_signature_dict = mime_dict["full_signatures"][
                    full_signature_key
                ]
                correct_signature = current_signature_dict["signature"]
                correct_signature_length = current_signature_dict["signature_length"]
                matching_signature = file_content[:correct_signature_length]
                logging.debug(f"[Detector module] - {matching_signature=}")
                if correct_signature == matching_signature:
                    return mime_type

    return "__unknown"


def check_media_signature(file_object, detection_data):
    logging.info("[Detector module] - Checking media signature")
    file_content = file_object.content
    file_signature_mime = match_file_signature(file_content)

    if file_signature_mime != "__unknown":
        logging.debug(f"[Detector module] - Signature correct: {file_signature_mime}")
        detection_data["file"]["signature_mime"] = file_signature_mime
        mime_whitelist_result = check_mime_against_whitelist(file_signature_mime)
        detection_data["checks"]["whitelisted_signature_mime"][
            "result"
        ] = mime_whitelist_result
        if not mime_whitelist_result:
            detection_data["file"]["block"] = True
            detection_data["file"]["block_reasons"].append("whitelist_file_signature")
        detection_data["checks"]["validation_signature"]["result"] = True
    else:
        logging.debug("[Detector module] - Signature unknown")
        detection_data["file"]["signature_mime"] = "__unknown"

    detection_data["checks"]["whitelisted_signature_mime"]["done"] = True
    detection_data["checks"]["validation_signature"]["done"] = True
    detection_data["sanitization_tasks"]["clean_structure"] = True

    return detection_data


def guess_mime_type_and_maliciousness(detection_data):
    logging.info("[Detector module] - Guessing MIME type")

    guessing_scores = {mime_type: 0 for mime_type in list(MIME_TYPES.keys())}
    total_points_given = 0

    # Adding file signature information
    file_signature_mime = detection_data["file"]["signature_mime"]
    if file_signature_mime in guessing_scores.keys():
        guessing_scores[file_signature_mime] += 1
    total_points_given += 1

    # Adding file extension information
    main_file_extension = detection_data["file"]["extensions"][0]
    main_mime_type = file_extension_to_mime_type(main_file_extension)
    if main_mime_type in guessing_scores.keys():
        guessing_scores[main_mime_type] += 1
    total_points_given += 1

    # Adding Content-Type header information
    content_type_mime = detection_data["file"]["request_header_mime"]
    if content_type_mime in guessing_scores.keys():
        guessing_scores[content_type_mime] += 1
    total_points_given += 1

    # Evaluating maliciousness
    sorted_guessing_scores = {
        k: v for k, v in sorted(guessing_scores.items(), key=lambda item: item[1])
    }
    logging.debug(f"[Detector module] - {pprint.pformat(sorted_guessing_scores)}")
    logging.debug(f"[Detector module] - {total_points_given=}")

    guessed_mime_type = max(guessing_scores.items(), key=operator.itemgetter(1))[0]
    correct_ratio = guessing_scores[guessed_mime_type] / total_points_given
    malicious = correct_ratio < DETECTOR_SENSITIVITY
    logging.debug(
        f"[Detector module] - Malicious: {malicious} - Score: ({guessing_scores[guessed_mime_type]}/{total_points_given}) => {correct_ratio*100}%"
    )

    # Setting detection data
    detection_data["file"]["guessed_mime"] = guessed_mime_type
    detection_data["file"]["malicious"] = malicious

    return detection_data


def run_detection(init_post_request, converted_file_objects):
    logging.info("[Detector module] - Starting detection")

    files_detection_data = {}

    for file_object_key in converted_file_objects:

        file_detection_data = copy.deepcopy(FILE_DETECTION_DATA_TEMPLATE)

        converted_file_object = converted_file_objects[file_object_key]

        # Independent checks
        file_detection_data = get_file_size(converted_file_object, file_detection_data)
        file_detection_data = check_file_size_allowed(file_detection_data)
        file_detection_data = get_request_header_mime(
            converted_file_object, file_detection_data
        )
        file_detection_data = check_file_exif_data(
            converted_file_object, file_detection_data
        )
        file_detection_data = check_filename(converted_file_object, file_detection_data)
        file_detection_data = check_media_signature(
            converted_file_object, file_detection_data
        )

        # Dependent checks => order important
        file_detection_data = check_signature_match_main_file_extension(
            file_detection_data
        )
        file_detection_data = guess_mime_type_and_maliciousness(file_detection_data)

        files_detection_data[file_object_key] = file_detection_data

    return files_detection_data