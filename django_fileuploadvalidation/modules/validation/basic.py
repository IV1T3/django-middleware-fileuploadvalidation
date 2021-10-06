import logging
import mimetypes
import operator
import pprint

import magic

from ..helper import add_point_to_guessed_file_type

from ...settings import (
    DETECTOR_SENSITIVITY,
    UPLOAD_MIME_TYPE_WHITELIST,
    FILE_SIZE_LIMIT,
    FILENAME_LENGTH_LIMIT,
)


def check_malicious_keywords(file):
    logging.debug("[Validation module] - Validating keywords")
    # TODO:
    # - Implement more efficient way to check for keywords
    # - Try to avoid using overlapping keywords but keep file
    #   type distinction for future use
    keywords = {
        "<?": 0,
        "<?=": 0,
        "<?php": 0,
        "?> ": 0,
        "<script>": 0,
        "#!": 0,
        "#!/": 0,
        "#!/bin/sh": 0,
        "#!/bin/bash": 0,
        "#!/usr/bin/pwsh": 0,
        "#!/usr/bin/env python3": 0,
        "#!/usr/bin/env sh": 0,
        "$_": 0,
        "base64": 0,
        "eval": 0,
    }

    found = False

    for line in file.content.splitlines():
        for keyword in keywords:
            if keyword.encode() in line:
                pos = line.index(keyword.encode())
                line_seq_following = line[pos : pos + 50]
                try:
                    line_seq_following.decode("ascii")
                    keywords[keyword] += 1
                    found = True
                    logging.warning(
                        "[Validation module] - ASCII Decoding POSSIBLE: %s",
                        line_seq_following,
                    )
                except UnicodeDecodeError:
                    logging.debug("ASCII Decoding not possible")
                    continue

    found_keywords = {key: val for key, val in keywords.items() if val > 0}

    print(f"{found_keywords=}")

    file.detection_results.found_keywords = found_keywords
    file.validation_results.keyword_search_ok = found

    # TODO: Currently too restrictive, basically blocks every file
    # if found:
    #     file.block = True
    #     file.append_block_reason("malicious_keywords_found")
    #     logging.warning(
    #         f"[Validation module] - Blocking file: malicious_keywords_found"
    #     )

    return file


def match_file_signature(file):
    logging.debug("[Validation module] - Matching file signature")

    return magic.from_buffer(file.content, mime=True)


def get_filename_splits(file_object):
    file_name_splits = list(
        map(lambda x: x.lower(), file_object.basic_information.name.split("."))
    )

    return file_name_splits


def check_file_size_allowed(file):
    """
    Check if the file size is within the allowed limits.
    """
    logging.debug("[Validation module] - Validating file size")

    file_size_ok = file.basic_information.size / 1000 <= FILE_SIZE_LIMIT
    file.validation_results.file_size_ok = file_size_ok

    if not file_size_ok:
        file.block = True
        file.append_block_reason("file_size_too_big")
        logging.warning(f"[Validation module] - Blocking file: file_size_too_big")

    return file


def check_mime_against_whitelist(mime_to_check):
    return mime_to_check in UPLOAD_MIME_TYPE_WHITELIST


def check_request_header_mime(file):
    """
    Check if the request header mime is whitelisted.
    """
    logging.debug(
        "[Validation module] - Validating request header MIME type against whitelist"
    )

    mime_whitelist_result = check_mime_against_whitelist(
        file.basic_information.content_type
    )

    file.validation_results.request_mime_ok = mime_whitelist_result

    if not mime_whitelist_result:
        file.block = True
        file.append_block_reason("request_mime_not_whitelisted")
        logging.warning(
            f"[Validation module] - Blocking file: request_mime_not_whitelisted"
        )

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
        file.block = True
        file.append_block_reason("mime_manipulation")
        logging.warning(f"[Validation module] - Blocking file: mime_manipulation")

    return file


def check_file_signature(file):
    """
    Check if the file signature is whitelisted.
    """
    logging.debug("[Validation module] - Validating file signature")

    mime_whitelist_result = check_mime_against_whitelist(
        file.detection_results.signature_mime
    )
    file.validation_results.signature_mime_ok = mime_whitelist_result
    if not mime_whitelist_result:
        file.block = True
        file.append_block_reason("signature_mime_not_whitelisted")
        logging.warning(
            f"[Validation module] - Blocking file: signature_mime_not_whitelisted"
        )

    return file


def check_filename_length(file):
    """
    Check if the filename length is within the allowed limits.
    """
    logging.debug("[Validation module] - Validating filename length")

    length_ok = len(file.basic_information.name) <= FILENAME_LENGTH_LIMIT
    file.validation_results.filename_length_ok = length_ok

    if not length_ok:
        file.block = True
        file.append_block_reason("filename_length_too_long")
        logging.warning(
            f"[Validation module] - Blocking file: filename_length_too_long"
        )

    return file


def check_filename_extensions(file):
    """
    Check if all filename extensions are whitelisted.
    """
    logging.debug("[Validation module] - Validating all filename extensions")

    mime_whitelist_results = []
    for single_extension in file.detection_results.extensions:
        curr_file_extension_mime = mimetypes.guess_type("name." + single_extension)[0]
        mime_whitelist_results.append(
            check_mime_against_whitelist(curr_file_extension_mime)
        )

    all_extensions_whitelisted = all(mime_whitelist_results)

    file.validation_results.extensions_whitelist_ok = all_extensions_whitelisted
    if not all_extensions_whitelisted:
        file.block = True
        file.append_block_reason("extension_not_whitelisted")
        logging.warning(
            f"[Validation module] - Blocking file: extension_not_whitelisted"
        )

    # TODO: Add detection of alternate media file extensions such as .php5

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
            file.block = True
            file.append_block_reason("null_byte_injection")
            logging.warning(f"[Validation module] - Blocking file: null_byte_injection")

    return file


def guess_mime_type_and_maliciousness(file):
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
    correct_ratio = guessing_scores[guessed_mime_type] / total_points_overall
    malicious = correct_ratio < DETECTOR_SENSITIVITY
    logging.info(
        f"[Validation module] - Malicious: {malicious} - Score: ({guessing_scores[guessed_mime_type]}/{total_points_overall}) => {correct_ratio*100}%"
    )

    # Setting detection data
    file.detection_results.guessed_mime = guessed_mime_type
    file.validation_results.malicious = malicious

    if malicious:
        file.block = True
        file.append_block_reason("malicious")
        logging.warning(f"[Validation module] - Blocking file: malicious")

    return file


def validate_file(file):
    logging.debug("[Validation module] - Starting basic detection")

    # Retrieve basic file information
    filename_splits = get_filename_splits(file)
    file.detection_results.filename_splits = filename_splits
    file.detection_results.extensions = filename_splits[1:]

    # Detecting file signature
    signature_mime = match_file_signature(file)
    file.detection_results.signature_mime = signature_mime
    file = add_point_to_guessed_file_type(file, signature_mime)

    # Perform generic keyword based search
    file = check_malicious_keywords(file)

    # Validate file information
    file = check_file_size_allowed(file)
    file = check_request_header_mime(file)
    file = check_signature_and_request_mime_match_file_extensions(file)
    file = check_file_signature(file)
    file = check_filename_length(file)
    file = check_filename_extensions(file)
    file = check_filename_for_null_byte_injections(file)
    file = guess_mime_type_and_maliciousness(file)

    return file
