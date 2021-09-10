import clamd
import copy
import logging

from io import BytesIO

from ...data.filedetectiondata import FILE_DETECTION_DATA_TEMPLATE
from ...data.filesignatures import FILE_SIGNATURES
from ...settings import CLAMAV_USAGE


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


def get_clamAV_results(file_object):
    # Connects to UNIX socket on /var/run/clamav/clamd.ctl
    clam_daemon = clamd.ClamdUnixSocket()

    clamd_res = clam_daemon.instream(BytesIO(file_object.content))

    return clamd_res["stream"][0]


def run_detection(converted_file_objects):
    logging.info("[Detector module] - Starting detection")

    files_detection_data = {}

    for conv_file_obj_key, conv_file_obj in converted_file_objects.items():

        file_detection_data = copy.deepcopy(FILE_DETECTION_DATA_TEMPLATE)

        # file_detection_data["file"]["size"] = conv_file_obj.size
        # file_detection_data["file"]["request_header_mime"] = conv_file_obj.content_type
        # file_detection_data["file"]["filename_length"] = len(conv_file_obj.name)
        file_detection_data["file"]["filename_splits"] = get_filename_splits(
            conv_file_obj
        )
        file_detection_data["file"]["extensions"] = file_detection_data["file"][
            "filename_splits"
        ][1:]
        file_detection_data["file"]["signature_mime"] = match_file_signature(
            conv_file_obj
        )

        if CLAMAV_USAGE:
            clamav_res = get_clamAV_results(conv_file_obj)
            if clamav_res == "FOUND":
                file_detection_data["file"]["block"] = True
                file_detection_data["file"]["block_reasons"].append("ClamAV detection")

        files_detection_data[conv_file_obj_key] = file_detection_data

    return files_detection_data
