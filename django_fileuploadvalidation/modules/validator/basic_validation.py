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

    file_size_ok = file_obj.basic_information.size / 1000 <= FILE_SIZE_LIMIT
    file_obj.validation_results.file_size_ok = file_size_ok

    if not file_size_ok:
        file_obj.block = True
        file_obj.append_block_reason("file_size_too_big")

    return file_obj


def check_request_header_mime(file_obj):
    """
    Check if the request header mime is whitelisted.
    """
    logging.info(
        "[Validator module - Basic] - Validating request header MIME type against whitelist"
    )

    mime_whitelist_result = check_mime_against_whitelist(
        file_obj.basic_information.content_type
    )
    file_obj.validation_results.request_mime_ok = mime_whitelist_result

    if not mime_whitelist_result:
        file_obj.block = True
        file_obj.append_block_reason("request_mime_not_whitelisted")

    return file_obj


def check_signature_and_request_mime_match_file_extensions(file_obj):
    """
    Check if the signature and request mime match the file extensions.
    """

    extension_matchings = []

    for single_file_extension in file_obj.detection_results.extensions:
        file_extension_mime = mimetypes.guess_type("name." + single_file_extension)[0]
        extension_matches = (
            file_extension_mime
            == file_obj.detection_results.signature_mime
            == file_obj.basic_information.content_type
        )
        extension_matchings.append(extension_matches)

    all_extensions_match = all(extension_matchings)

    file_obj.validation_results.matching_extension_signature_request_ok = (
        all_extensions_match
    )
    file_obj.attack_results.mime_manipulation = not all_extensions_match

    if not all_extensions_match:
        file_obj.block = True
        file_obj.append_block_reason("mime_manipulation")

    return file_obj


def check_file_signature(file_obj):
    """
    Check if the file signature is whitelisted.
    """
    logging.info("[Validator module - Basic] - Validating file signature")

    mime_whitelist_result = check_mime_against_whitelist(
        file_obj.detection_results.signature_mime
    )
    file_obj.validation_results.signature_mime_ok = mime_whitelist_result
    if not mime_whitelist_result:
        file_obj.block = True
        file_obj.append_block_reason("signature_mime_not_whitelisted")

    return file_obj


def check_filename_length(file_obj):
    """
    Check if the filename length is within the allowed limits.
    """
    logging.info("[Validator module - Basic] - Validating filename length")

    length_ok = len(file_obj.basic_information.name) <= FILENAME_LENGTH_LIMIT
    file_obj.validation_results.filename_length_ok = length_ok

    if not length_ok:
        file_obj.block = True
        file_obj.append_block_reason("filename_length_too_long")

    return file_obj


def check_filename_extensions(file_obj):
    """
    Check if all filename extensions are whitelisted.
    """
    logging.info("[Validator module - Basic] - Validating all filename extensions")

    mime_whitelist_results = []
    for single_extension in file_obj.detection_results.extensions:
        curr_file_extension_mime = mimetypes.guess_type("name." + single_extension)[0]
        mime_whitelist_results.append(
            check_mime_against_whitelist(curr_file_extension_mime)
        )

    all_extensions_whitelisted = all(mime_whitelist_results)

    file_obj.validation_results.extensions_whitelist_ok = all_extensions_whitelisted
    if not all_extensions_whitelisted:
        file_obj.block = True
        file_obj.append_block_reason("extension_not_whitelisted")

    # TODO: Add detection of alternate media file extensions such as .php5

    return file_obj


def check_filename_for_null_byte_injections(file_obj):
    logging.info("[Validator module - Basic] - Validating for null byte injections")

    for file_name_split in file_obj.detection_results.filename_splits:
        null_byte_found = (
            "0x00" in file_name_split
            or "%00" in file_name_split
            or "\0" in file_name_split
        )
        file_obj.attack_results.null_byte_injection = null_byte_found
        if null_byte_found:
            file_obj.block = True
            file_obj.append_block_reason("null_byte_injection")

    return file_obj


def guess_mime_type_and_maliciousness(file_obj):
    logging.info("[Validator module - Basic] - Guessing MIME type")

    guessing_scores = {mime_type: 0 for mime_type in list(mimetypes.types_map.values())}
    total_points_given = 0
    total_points_overall = 0

    # Adding file signature information
    file_signature_mime = file_obj.detection_results.signature_mime
    if file_signature_mime in guessing_scores.keys():
        guessing_scores[file_signature_mime] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding file extension information
    main_file_extension = file_obj.detection_results.extensions[0]
    main_mime_type = mimetypes.guess_type("name." + main_file_extension)[0]
    if main_mime_type in guessing_scores.keys():
        guessing_scores[main_mime_type] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding Content-Type header information
    content_type_mime = file_obj.basic_information.content_type
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
    file_obj.detection_results.guessed_mime = guessed_mime_type
    file_obj.validation_results.malicious = malicious

    if malicious:
        file_obj.block = True
        file_obj.append_block_reason("malicious_mime_type")

    return file_obj


def run_validation(file_objects):
    logging.info("[Validator module - Basic] - Starting basic validation")

    basic_validation_successful = True

    for (
        conv_file_obj_key,
        conv_file_object,
    ) in file_objects.items():

        file_objects[conv_file_obj_key] = check_file_size_allowed(conv_file_object)
        file_objects[conv_file_obj_key] = check_request_header_mime(conv_file_object)
        file_objects[
            conv_file_obj_key
        ] = check_signature_and_request_mime_match_file_extensions(conv_file_object)
        file_objects[conv_file_obj_key] = check_file_signature(conv_file_object)
        file_objects[conv_file_obj_key] = check_filename_length(conv_file_object)
        file_objects[conv_file_obj_key] = check_filename_extensions(conv_file_object)
        file_objects[conv_file_obj_key] = check_filename_for_null_byte_injections(
            conv_file_object
        )
        file_objects[conv_file_obj_key] = guess_mime_type_and_maliciousness(
            conv_file_object
        )

        if conv_file_object.block:
            basic_validation_successful = False
            break

    return basic_validation_successful, file_objects
