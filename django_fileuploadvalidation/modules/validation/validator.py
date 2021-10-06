import clamd
import logging

from io import BytesIO

from . import basic, image, application, video
from ...settings import CLAMAV_USAGE


def get_clamAV_results(file_object):
    # Connects to UNIX socket on /var/run/clamav/clamd.ctl
    clam_daemon = clamd.ClamdUnixSocket()

    clamd_res = clam_daemon.instream(BytesIO(file_object.content))

    return clamd_res["stream"][0]


def validate(files, options):
    logging.debug("[Validation module] - Starting validation")

    block_upload = False

    for file_name, file in files.items():

        if not block_upload:
            if CLAMAV_USAGE:
                clamav_res = get_clamAV_results(file)
                malicious = clamav_res == "FOUND"
                if malicious:
                    block_upload = True
                    file.block = True
                    file.append_block_reason("ClamAV detection")
                    logging.warning(
                        f"[Validation module] - Blocking file: ClamAV detection"
                    )

            if not file.block:

                # Perform basic file validation
                file = basic.validate_file(file)

                if not file.block:

                    # Get guessed file type
                    file_type = file.detection_results.guessed_mime

                    # Perform file type specific validation
                    if file_type.startswith("application"):
                        file = application.validate_file(file)
                    elif file_type.startswith("audio"):
                        pass
                    elif file_type.startswith("image"):
                        file = image.validate_file(file)
                    elif file_type.startswith("text"):
                        pass
                    elif file_type.startswith("video"):
                        file = video.validate_file(file)
                    # else:
                    #    file = image.validate_file(file)

            logging.debug(
                f"[Validation module] - Current block status: {file.block} => {file.block_reasons}"
            )

            if file.block:
                block_upload = True

    return files, block_upload
