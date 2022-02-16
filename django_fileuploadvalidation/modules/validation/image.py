import io
import logging

from PIL import Image as ImageP
from wand.image import Image as ImageW


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

    logging.debug("[Validation module] - CHECK: Image integrity - PASSED")
    return True


def validate_file(file):
    logging.debug("[Validation module] - Starting image validation")

    file.validation_results.file_integrity_ok = check_integrity(file)
    file.validation_results.file_integrity_check_done = True

    logging.debug("[Validation module] - Validation: Image - DONE")

    return file
