import logging
import mimetypes
import operator
import pprint

from ...settings import (
    DETECTOR_SENSITIVITY,
    UPLOAD_MIME_TYPE_WHITELIST,
    FILE_SIZE_LIMIT,
    FILENAME_LENGTH_LIMIT,
)


def check_mime_against_whitelist(mime_to_check):
    return mime_to_check in UPLOAD_MIME_TYPE_WHITELIST


#######################################
### Starting basic validation tasks ###
#######################################


def check_file_size_allowed(file_obj):
    """
    Check if the file size is within the allowed limits.
    """
    logging.info("[Validator module - Basic] - Validating file size")
    # file_size = detection_data["file"]["size"] / 1000
    if file_obj.basic_information.size / 1000 <= FILE_SIZE_LIMIT:
        file_obj.validation_results.file_size_ok = True
        # detection_data["checks"]["validation_file_size"]["result"] = True
    else:
        file_obj.validation_results.file_size_ok = False
        # detection_data["checks"]["validation_file_size"]["result"] = False

        file_obj.attack_results.file_size_too_big = True
        # detection_data["recognized_attacks"]["file_size_large"] = True

        file_obj.block = True
        # detection_data["file"]["block"] = True

        file_obj.block_reasons.append("file_size_too_big")
        # detection_data["file"]["block_reasons"].append("invalid_file_size")

    # detection_data["checks"]["validation_file_size"]["done"] = True

    return file_obj


def check_request_header_mime(file_obj):
    """
    Check if the request header mime is whitelisted.
    """
    logging.info(
        "[Validator module - Basic] - Validating request header MIME type against whitelist"
    )

    mime_whitelist_result = check_mime_against_whitelist(
        detection_data["file"]["request_header_mime"]
    )

    detection_data["checks"]["whitelisted_request_mime"]["done"] = True
    detection_data["checks"]["whitelisted_request_mime"][
        "result"
    ] = mime_whitelist_result

    if not mime_whitelist_result:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("whitelist_content_type")

    return detection_data


def check_signature_and_request_mime_match_file_extensions(file_obj):
    """
    Check if the signature and request mime match the file extensions.
    """
    file_request_mime = detection_data["file"]["request_header_mime"]
    file_signature_mime = detection_data["file"]["signature_mime"]

    extension_matchings = []

    for single_file_extension in detection_data["file"]["extensions"]:
        file_extension_mime = mimetypes.guess_type("name." + single_file_extension)[0]
        extension_matches = (
            file_extension_mime == file_signature_mime == file_request_mime
        )
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


def check_media_signature(file_obj):
    """
    Check if the media signature is whitelisted.
    """
    logging.info("[Validator module - Basic] - Validating media signature")

    file_signature_mime = detection_data["file"]["signature_mime"]
    mime_whitelist_result = check_mime_against_whitelist(file_signature_mime)
    detection_data["checks"]["whitelisted_signature_mime"][
        "result"
    ] = mime_whitelist_result

    if not mime_whitelist_result:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("whitelist_file_signature")
    detection_data["checks"]["validation_signature"]["result"] = True

    detection_data["checks"]["whitelisted_signature_mime"]["done"] = True
    detection_data["checks"]["validation_signature"]["done"] = True
    detection_data["sanitization_tasks"]["clean_structure"] = True

    return detection_data


def check_filename_length(file_obj):
    """
    Check if the filename length is within the allowed limits.
    """
    logging.info("[Validator module - Basic] - Validating filename length")
    if detection_data["file"]["filename_length"] < FILENAME_LENGTH_LIMIT:
        detection_data["checks"]["validation_filename_length"]["result"] = True
    else:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("validation_filename_length")

    detection_data["checks"]["validation_filename_length"]["done"] = True

    return detection_data


def check_filename_extensions(file_obj):
    """
    Check if all filename extensions are whitelisted.
    """
    logging.info("[Validator module - Basic] - Validating all filename extensions")
    file_extensions = detection_data["file"]["extensions"]

    if len(file_extensions) > 1:
        detection_data["recognized_attacks"]["additional_file_extensions"] = True

    mime_whitelist_results = []
    for single_extension in file_extensions:
        curr_file_extension_mime = mimetypes.guess_type("name." + single_extension)[0]
        mime_whitelist_results.append(
            check_mime_against_whitelist(curr_file_extension_mime)
        )

    all_extensions_whitelisted = all(mime_whitelist_results)

    detection_data["checks"]["whitelisted_extensions_mime"]["done"] = True
    detection_data["checks"]["whitelisted_extensions_mime"][
        "result"
    ] = all_extensions_whitelisted

    if not all_extensions_whitelisted:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("whitelist_file_extension")

    # TODO: Add detection of alternate media file extensions such as .php5

    return detection_data


def check_filename_for_null_byte_injections(file_obj):
    logging.info("[Validator module - Basic] - Validating for null byte injections")

    for file_name_split in detection_data["file"]["filename_splits"]:
        if (
            "0x00" in file_name_split
            or "%00" in file_name_split
            or "\0" in file_name_split
        ):
            detection_data["recognized_attacks"]["null_byte_injection"] = True

    return detection_data


def guess_mime_type_and_maliciousness(file_obj):
    logging.info("[Validator module - Basic] - Guessing MIME type")

    guessing_scores = {mime_type: 0 for mime_type in list(mimetypes.types_map.values())}
    total_points_given = 0
    total_points_overall = 0

    # Adding file signature information
    file_signature_mime = detection_data["file"]["signature_mime"]
    if file_signature_mime in guessing_scores.keys():
        guessing_scores[file_signature_mime] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding file extension information
    main_file_extension = detection_data["file"]["extensions"][0]
    main_mime_type = mimetypes.guess_type("name." + main_file_extension)[0]
    if main_mime_type in guessing_scores.keys():
        guessing_scores[main_mime_type] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding Content-Type header information
    content_type_mime = detection_data["file"]["request_header_mime"]
    if content_type_mime in guessing_scores.keys():
        guessing_scores[content_type_mime] += 1
        total_points_given += 1
    total_points_overall += 1

    # Evaluating maliciousness
    sorted_guessing_scores = {
        k: v
        for k, v in sorted(guessing_scores.items(), key=lambda item: item[1])
        if v > 0
    }
    logging.debug(
        f"[Validator module - Basic] - {pprint.pformat(sorted_guessing_scores)}"
    )
    logging.debug(
        f"[Validator module - Basic] - {total_points_overall=} - {total_points_given=}"
    )

    guessed_mime_type = max(guessing_scores.items(), key=operator.itemgetter(1))[0]
    correct_ratio = guessing_scores[guessed_mime_type] / total_points_overall
    malicious = correct_ratio < DETECTOR_SENSITIVITY
    logging.debug(
        f"[Validator module - Basic] - Malicious: {malicious} - Score: ({guessing_scores[guessed_mime_type]}/{total_points_overall}) => {correct_ratio*100}%"
    )

    # Setting detection data
    detection_data["file"]["guessed_mime"] = guessed_mime_type
    detection_data["file"]["malicious"] = malicious

    if malicious:
        detection_data["file"]["block"] = True
        detection_data["file"]["block_reasons"].append("Malicious")

    return detection_data


def run_validation(file_objects):
    logging.info("[Validator module - Basic] - Starting basic validation")

    basic_validation_successful = True
    # files_basic_detection_data__VALIDATED = {}

    for (
        conv_file_obj_key,
        conv_file_object,
    ) in file_objects.items():

        file_objects[conv_file_obj_key] = check_file_size_allowed(conv_file_object)
        file_objects[conv_file_obj_key] = check_request_header_mime(conv_file_object)
        file_objects[
            conv_file_obj_key
        ] = check_signature_and_request_mime_match_file_extensions(conv_file_object)
        file_objects[conv_file_obj_key] = check_media_signature(conv_file_object)
        file_objects[conv_file_obj_key] = check_filename_length(conv_file_object)
        file_objects[conv_file_obj_key] = check_filename_extensions(conv_file_object)
        file_objects[conv_file_obj_key] = check_filename_for_null_byte_injections(
            conv_file_object
        )
        file_objects[conv_file_obj_key] = guess_mime_type_and_maliciousness(
            conv_file_object
        )

        # files_basic_detection_data__VALIDATED[
        #    conv_file_obj_key
        # ] = basic_detection_data__VAL

        if conv_file_object.block:
            basic_validation_successful = False
            break

        # if basic_detection_data__VAL["file"]["block"]:
        #    basic_validation_successful = False
        #    break

    return basic_validation_successful, file_objects
