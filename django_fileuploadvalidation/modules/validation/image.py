import io
import logging

from PIL import Image as ImageP
from wand.image import Image as ImageW


# def check_file_exif_data(file):
#     logging.debug("[Image Validation module] - Getting exif data")
#     exif_data = file.basic_information.exif_data
#     # logging.debug(f"[Validation module] - {exif_data=}")
#     # TODO: Add detection of exif injection
#     malicious_injections = ["<?", "<script>", "$_", "base64", "eval"]
#     for malicious_injection in malicious_injections:
#         if malicious_injection in exif_data:
#             logging.warning(
#                 f"[Validation module] - {malicious_injection} found in exif data"
#             )
#             file.attack_results.exif_injection = True
#             file.block = True
#             file.append_block_reason("exif_injection")
#             logging.warning(
#                 f"[Validation module] - Blocking image file: exif_injection"
#             )

#             break

#     logging.info("[Validation module] - CHECK: Exif data - PASSED")

#     return file


def check_integrity(file):
    logging.debug("[Validation module] - Starting image integrity check")

    try:
        image = ImageP.open(io.BytesIO(file.content))
        image.verify()
        image.close()
    except Exception as e:
        logging.warning(
            f"[Validation module] - CHECK: Image integrity (1) - FAILED: {e}"
        )
        return False

    try:
        image = ImageP.open(io.BytesIO(file.content))
        image.transpose(ImageP.FLIP_LEFT_RIGHT)
        image.close()
    except Exception as e:
        logging.warning(
            f"[Validation module] - CHECK: Image integrity (2) - FAILED: {e}"
        )
        return False

    try:
        image = ImageW(file=io.BytesIO(file.content))
        _ = image.flip
        image.close()
    except Exception as e:
        logging.warning(
            f"[Validation module] - CHECK: Image integrity (3) - FAILED: {e}"
        )
        return False

    logging.info("[Validation module] - CHECK: Image integrity - PASSED")
    return True


def validate_file(file):
    logging.debug("[Validation module] - Starting image validation")

    file.detection_results.file_integrity = check_integrity(file)

    if file.detection_results.file_integrity:
        pass
        # file = check_file_exif_data(file)
    else:
        file.block = True
        file.append_block_reason("integrity_check_failed")
        logging.warning(
            f"[Validation module] - Blocking image file: integrity_check_failed"
        )

    logging.info("[Validation module] - Validation: Image - DONE")

    return file
