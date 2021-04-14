import io
import logging
import uuid

from PIL import Image, UnidentifiedImageError

from .helper import mime_type_to_file_extension

from ..data.filesanitizationdata import FILE_SANITITAZION_DATA_TEMPLATE


def rerender_image_data(file_object, mime_type):
    logging.info("[Sanitizer module] - Rerendering image")

    image_buff = io.BytesIO(file_object.content)
    sanitized_image_buff = io.BytesIO()

    conversion = "RGBA" if mime_type == "image/png" else "RGB"
    format = mime_type_to_file_extension(mime_type)[1:].upper()

    success = False

    try:
        sanitized_image = Image.open(image_buff).convert(conversion)
        sanitized_image.save(sanitized_image_buff, format)

        sanitized_image_buff.seek(0)
        file_object.content = sanitized_image_buff.read()
        success = True

    except UnidentifiedImageError:
        logging.info("[Sanitizer module] - Image couldn't been rerendered.")
        file_object.content = b""
        file_object.block = True

    finally:
        image_buff.close()
        sanitized_image_buff.close()

    return file_object, success


def sanitization_task__clean_exif(file_object, file_detection_data):
    file_object.exif_data = ""
    return file_object


def sanitization_task__clean_structure(file_object, file_detection_data):
    logging.info("[Sanitizer module - Tasks] - Clean structure")

    successfull_cleansing = False

    main_mime = file_detection_data["file"]["guessed_mime"].split("/")[0]

    logging.debug(f"{main_mime=}")

    if main_mime == "image":
        sanitized_file_object, successfull_cleansing = rerender_image_data(
            file_object, file_detection_data["file"]["guessed_mime"]
        )
    else:
        sanitized_file_object = file_object

    return sanitized_file_object, successfull_cleansing


def sanitization_task__create_random_filename_with_guessed_extension(
    file_object, file_detection_data
):
    logging.info("[Sanitizer module - Tasks] - Creating random file name")
    file_extension = mime_type_to_file_extension(
        file_detection_data["file"]["guessed_mime"]
    )
    unique_file_name = str(uuid.uuid4()) + file_extension
    file_object.name = unique_file_name

    return file_object


def iterate_sanitization_tasks(file_object, file_detection_data):
    logging.info("[Sanitizer module] - Starting sanitization tasks")
    file_sanitization_data = FILE_SANITITAZION_DATA_TEMPLATE
    file_sanitization_tasks = file_detection_data["sanitization_tasks"]

    if file_sanitization_tasks["start_sanitization"]:
        if file_sanitization_tasks["clean_exif"]:
            file_object = sanitization_task__clean_exif(
                file_object, file_detection_data
            )
            file_sanitization_data["cleansed_exif"] = True

        if file_sanitization_tasks["clean_structure"]:
            file_object, successfull_cleansing = sanitization_task__clean_structure(
                file_object, file_detection_data
            )
            file_sanitization_data["cleansed_structure"] = successfull_cleansing

        if file_sanitization_tasks["create_random_filename_with_guessed_extension"]:
            file_object = (
                sanitization_task__create_random_filename_with_guessed_extension(
                    file_object, file_detection_data
                )
            )
            file_sanitization_data[
                "created_random_filename_with_guessed_extension"
            ] = True

    return file_sanitization_data, file_object


def run_sanitization(init_post_request, converted_file_objects, detection_data):
    logging.info("[Sanitizer module] - Starting sanitization")

    all_sanitized_data = {}
    all_sanitized_file_objects = {}

    for file_object in converted_file_objects:

        file_sanitization_data, sanitized_file_object = iterate_sanitization_tasks(
            converted_file_objects[file_object],
            detection_data[file_object],
        )

        all_sanitized_data[file_object] = file_sanitization_data
        all_sanitized_file_objects[file_object] = sanitized_file_object

    return all_sanitized_data, all_sanitized_file_objects