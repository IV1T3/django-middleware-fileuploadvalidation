import io
import logging

from PIL import Image


def check_file_exif_data(file):
    logging.info("[Image Detector module] - Getting exif data")
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
            break

    return file


def check_integrity(file):
    image_buff = io.BytesIO(file.content)

    try:
        image = Image.open(image_buff)
        image.verify()
        image.close()

        image = Image.open(image_buff)
        image.transpose(Image.FLIP_LEFT_RIGHT)
        image.close()

        logging.info("[Detector module] - File integrity check passed")

        return True
    except Exception as e:
        logging.warning(f"[Detector module] - Image integrity check: {e}")
        return False


def detect_file(file):
    logging.info("[Detector module] - Starting image detection")

    file.file_integrity = check_integrity(file)

    if file.file_integrity:
        file = check_file_exif_data(file)
    else:
        file.block = True
        file.append_block_reason("File integrity check failed")

    return file
