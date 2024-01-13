import io
import logging
import mimetypes
import random

from PIL import Image, UnidentifiedImageError


def rerender_and_randomize_image_data(file_object, mime_type):
    logging.debug("[Sanitizer module - Image] - Rerendering and randomizing image")
    image_buff = io.BytesIO(file_object.content)
    sanitized_image_buff = io.BytesIO()

    conversion = "RGBA" if mime_type == "image/png" else "RGB"
    format = mimetypes.guess_extension(mime_type)[1:].upper()
    if format == "JPG":
        format = "JPEG"

    success = False

    try:
        logging.debug("[Sanitizer module - Image] - Starting to rerender image")
        sanitized_image = Image.open(image_buff).convert(conversion)
        sanitized_image.save(sanitized_image_buff, format)

        logging.debug("[Sanitizer module - Image] - Starting to randomize image")
        pixels = sanitized_image.load()

        for i in range(sanitized_image.size[0]):
            if i % random.randrange(1, 10) == 0:
                for j in range(sanitized_image.size[1]):
                    if i * j % random.randrange(1, 10) == 0:
                        pixel_list = list(pixels[i, j])
                        for k in range(len(pixel_list)):
                            noise_offset = random.randrange(2)
                            pixel_list[k] += (
                                -1 * noise_offset
                                if pixel_list[k] == 255
                                else noise_offset
                            )
                        pixel_tuple = tuple(pixel_list)
                        pixels[i, j] = pixel_tuple

        sanitized_image_buff.seek(0)
        file_object.content = sanitized_image_buff.read()
        success = True

    except UnidentifiedImageError:
        logging.debug("[Sanitizer module - Image] - Image couldn't been rerendered.")
        file_object.content = b""
        file_object.block = True

    finally:
        image_buff.close()
        sanitized_image_buff.close()

    return file_object, success


def sanitization_task__clean_exif(file_object):
    logging.debug("[Sanitizer module - Image] - TASK: Clean EXIF")
    file_object.exif_data = ""
    return file_object


def sanitization_task__clean_structure(file_object):
    logging.debug("[Sanitizer module - Image] - TASK: Clean structure")

    successful_cleansing = False

    main_mime = file_object.detection_results.guessed_mime.split("/")[0]

    if main_mime == "image":
        (
            sanitized_file_object,
            successful_cleansing,
        ) = rerender_and_randomize_image_data(
            file_object, file_object.detection_results.guessed_mime
        )
    else:
        sanitized_file_object = file_object

    return sanitized_file_object, successful_cleansing


def sanitize_file(file):
    logging.debug("[Sanitizer module] - Starting image sanitization")

    mimetypes.init()

    file = sanitization_task__clean_exif(file)
    file.sanitization_results.cleansed_exif = True

    file, successful_cleansing = sanitization_task__clean_structure(file)
    file.sanitization_results.cleansed_structure = successful_cleansing

    return file
