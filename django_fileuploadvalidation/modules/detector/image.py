import io
import logging

from PIL import Image as ImageP
from wand.image import Image as ImageW


def check_file_exif_data(file):
    logging.debug("[Image Detector module] - Getting exif data")
    exif_data = file.basic_information.exif_data
    # logging.debug(f"[Detector module] - {exif_data=}")
    # TODO: Add detection of exif injection
    malicious_injections = ["<?", "<script>", "$_", "base64", "eval"]
    for malicious_injection in malicious_injections:
        if malicious_injection in exif_data:
            logging.warning(
                f"[Detector module] - {malicious_injection} found in exif data"
            )
            file.attack_results.exif_injection = True
            file.block = True
            file.append_block_reason("exif_injection")
            logging.warning(f"[Detector module] - Blocking image file: exif_injection")

            break
    
    logging.info("[Detector module] - CHECK: Exif data - PASSED")

    return file


def check_integrity(file):
    logging.debug("[Detector module] - Starting image integrity check")
    
    try:
        image = ImageP.open(io.BytesIO(file.content))
        image.verify()
        image.close()
    except Exception as e:
        logging.warning(f"[Detector module] - CHECK: Image integrity (1) - FAILED: {e}")
        return False

    try:
        image = ImageP.open(io.BytesIO(file.content))
        image.transpose(ImageP.FLIP_LEFT_RIGHT)
        image.close()
    except Exception as e:
        logging.warning(f"[Detector module] - CHECK: Image integrity (2) - FAILED: {e}")
        return False
    
    try:
        image = ImageW(file=io.BytesIO(file.content))
        _ = image.flip
        image.close()
    except Exception as e:
        logging.warning(f"[Detector module] - CHECK: Image integrity (3) - FAILED: {e}")
        return False

    logging.info("[Detector module] - CHECK: Image integrity - PASSED")
    return True
    


def detect_file(file):
    logging.debug("[Detector module] - Starting image detection")

    file.detection_results.file_integrity = check_integrity(file)

    if file.detection_results.file_integrity:
        file = check_file_exif_data(file)
    else:
        file.block = True
        file.append_block_reason("integrity_check_failed")
        logging.warning(f"[Detector module] - Blocking image file: integrity_check_failed")

    return file
