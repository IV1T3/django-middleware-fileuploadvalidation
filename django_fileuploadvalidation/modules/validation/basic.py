import re
import logging
import mimetypes
import operator
import pprint
import os

import magic
import yara


from ..helper import add_point_to_guessed_file_type


def perform_yara_matching(file):
    """
    Perform YARA matching.
    """
    logging.debug("[Validation module] - Performing YARA matching")

    yara_dir_path = (
        os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            )
        )
        + "/vendor/yara"
    )

    rules = yara.compile(
        filepaths={
            file_name.split(".")[0]: os.path.join(yara_dir_path, file_name)
            for file_name in os.listdir(yara_dir_path)
        }
    )

    matches = rules.match(data=file.content)

    file.detection_results.yara_matches = matches

    return file


def match_file_signature(file):
    logging.debug("[Validation module] - Matching file signature")

    return magic.from_buffer(file.content, mime=True)


def get_filename_splits(file_object):
    file_name_splits = list(
        map(lambda x: x.lower(), file_object.basic_information.name.split("."))
    )

    return file_name_splits


def check_file_size_allowed(file, upload_config):
    """
    Check if the file size is within the allowed limits.
    """
    logging.debug("[Validation module] - Validating file size")

    file_size_ok = (
        file.basic_information.size / 1000 <= upload_config["file_size_limit"]
    )
    file.validation_results.file_size_ok = file_size_ok

    if not file_size_ok:
        logging.warning(f"[Validation module] - File size is too big.")

    return file


def check_mime_against_whitelist(mime_to_check, upload_config):
    return mime_to_check in upload_config["whitelist"]


def check_request_header_mime(file, upload_config):
    """
    Check if the request header mime is whitelisted.
    """
    logging.debug(
        "[Validation module] - Validating request header MIME type against whitelist"
    )

    mime_whitelist_result = check_mime_against_whitelist(
        file.basic_information.content_type, upload_config
    )

    file.validation_results.request_whitelist_ok = mime_whitelist_result

    if not mime_whitelist_result:
        logging.warning(f"[Validation module] - Content-Type not whitelisted")

    return file


def check_signature_and_request_mime_match_file_extensions(file):
    """
    Check if the signature and request mime match the file extensions.
    """

    extension_matchings = []

    for single_file_extension in file.detection_results.extensions:
        file_extension_mime = mimetypes.guess_type("name." + single_file_extension)[0]
        extension_matches = (
            file_extension_mime
            == file.detection_results.signature_mime
            == file.basic_information.content_type
        )
        extension_matchings.append(extension_matches)

    all_extensions_match = all(extension_matchings)

    file.validation_results.matching_extension_signature_request_ok = (
        all_extensions_match
    )
    file.attack_results.mime_manipulation = not all_extensions_match

    if not all_extensions_match:
        logging.warning(f"[Validation module] - Extension MIME does not match")

    return file


def check_file_signature(file, upload_config):
    """
    Check if the file signature is whitelisted.
    """
    logging.debug("[Validation module] - Validating file signature")

    mime_whitelist_result = check_mime_against_whitelist(
        file.detection_results.signature_mime, upload_config
    )
    file.validation_results.signature_whitelist_ok = mime_whitelist_result

    if not mime_whitelist_result:
        logging.warning(f"[Validation module] - Signature not whitelisted")

    return file


def check_filename_length(file, upload_config):
    """
    Check if the filename length is within the allowed limits.
    """
    logging.debug("[Validation module] - Validating filename length")

    length_ok = (
        len(file.basic_information.name) <= upload_config["filename_length_limit"]
    )
    file.validation_results.filename_length_ok = length_ok

    if not length_ok:
        logging.warning(f"[Validation module] - Filename length too long")

    return file


def check_filename_extensions(file, upload_config):
    """
    Check if all filename extensions are whitelisted.
    """
    logging.debug("[Validation module] - Validating all filename extensions")

    mime_whitelist_results = []
    for single_extension in file.detection_results.extensions:
        curr_file_extension_mime = mimetypes.guess_type("name." + single_extension)[0]
        mime_whitelist_results.append(
            check_mime_against_whitelist(curr_file_extension_mime, upload_config)
        )

    all_extensions_whitelisted = all(mime_whitelist_results)

    file.validation_results.extensions_whitelist_ok = all_extensions_whitelisted
    if not all_extensions_whitelisted:
        logging.warning(f"[Validation module] - Extension not whitelisted")

    # TODO: Add detection of alternate media file extensions such as .php5

    return file


def check_yara_rules(file):
    """
    Check if the file matches any YARA rules.
    """
    logging.debug("[Validation module] - Validating YARA rules")

    file.validation_results.yara_rules_ok = (
        len(file.detection_results.yara_matches) == 0
    )

    for match in file.detection_results.yara_matches:
        file.append_block_reason("YARA match: " + match.rule)

    return file


def check_filename_for_null_byte_injections(file):
    logging.debug("[Validation module] - Validating for null byte injections")

    for file_name_split in file.detection_results.filename_splits:
        null_byte_found = (
            "0x00" in file_name_split
            or "%00" in file_name_split
            or "\0" in file_name_split
        )
        file.attack_results.null_byte_injection = null_byte_found
        if null_byte_found:
            logging.warning(f"[Validation module] - Null byte injection found")

    return file


def guess_mime_type(file):
    logging.debug("[Validation module] - Guessing MIME type")

    guessing_scores = {mime_type: 0 for mime_type in list(mimetypes.types_map.values())}
    total_points_given = 0
    total_points_overall = 0

    # Adding file signature information
    file_signature_mime = file.detection_results.signature_mime
    if file_signature_mime in guessing_scores.keys():
        guessing_scores[file_signature_mime] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding file extension information
    main_file_extension = file.detection_results.extensions[0]
    main_mime_type = mimetypes.guess_type("name." + main_file_extension)[0]
    if main_mime_type in guessing_scores.keys():
        guessing_scores[main_mime_type] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding Content-Type header information
    content_type_mime = file.basic_information.content_type
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
    logging.info(f"[Validation module] - {pprint.pformat(sorted_guessing_scores)}")
    logging.info(
        f"[Validation module] - {total_points_overall=} - {total_points_given=}"
    )

    guessed_mime_type = max(guessing_scores.items(), key=operator.itemgetter(1))[0]
    file.detection_results.guessed_mime = guessed_mime_type

    return file


def validate_file(file, upload_config):
    logging.debug(
        f"{file.basic_information.name} - [Validation module] - Starting basic detection"
    )

    mimetypes.init()

    # Match YARA rules
    file = perform_yara_matching(file)

    # Retrieve basic file information
    filename_splits = get_filename_splits(file)
    file.detection_results.filename_splits = filename_splits
    file.detection_results.extensions = [filename_splits[-1]]
    main_file_extension = file.detection_results.extensions[0]
    main_extension_mime_type = mimetypes.guess_type("name." + main_file_extension)[0]
    file = add_point_to_guessed_file_type(file, main_extension_mime_type)

    # Detecting file signature
    signature_mime = match_file_signature(file)
    file.detection_results.signature_mime = signature_mime
    file = add_point_to_guessed_file_type(file, signature_mime)

    # Validate file information
    file = check_yara_rules(file)
    file = check_file_size_allowed(file, upload_config)
    file = check_request_header_mime(file, upload_config)
    file = check_signature_and_request_mime_match_file_extensions(file)
    file = check_file_signature(file, upload_config)
    file = check_filename_length(file, upload_config)
    file = check_filename_extensions(file, upload_config)
    file = check_filename_for_null_byte_injections(file)
    file = guess_mime_type(file)

    return file
