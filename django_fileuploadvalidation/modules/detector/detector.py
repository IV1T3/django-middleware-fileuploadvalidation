import clamd
import logging

from io import BytesIO

from . import basic, image, application
from ...settings import CLAMAV_USAGE


def get_clamAV_results(file_object):
    # Connects to UNIX socket on /var/run/clamav/clamd.ctl
    clam_daemon = clamd.ClamdUnixSocket()

    clamd_res = clam_daemon.instream(BytesIO(file_object.content))

    return clamd_res["stream"][0]


def detect(files):
    logging.info("[Detector module] - Starting detection")

    block_upload = False

    for file_name, file in files.items():

        if CLAMAV_USAGE:
            clamav_res = get_clamAV_results(file)
            malicious = clamav_res == "FOUND"
            if malicious:
                block_upload = True
                file.block = True
                file.append_block_reason("ClamAV detection")

        if not file.block:

            # Perform basic file detection
            file = basic.detect_file(file)

            # Get guessed file type
            file_type = file.detection_results.guessed_mime

            # Perform file type specific detection
            if file_type.startswith("application"):
                pass
            elif file_type.startswith("audio"):
                pass
            elif file_type.startswith("image"):
                file = image.detect_file(file)
            elif file_type.startswith("text"):
                pass
            elif file_type.startswith("video"):
                pass
            else:
                file = image.detect_file(file)

    return files, block_upload