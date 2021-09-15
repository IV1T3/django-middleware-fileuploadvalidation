import logging

from ...files import ImageFile


def base_file_objects_to_image_file_objects(base_files) -> dict:
    logging.info("[Converter module - Image] - Starting BaseFile to ImageFile objects")
    image_file_objects = base_files

    for base_file_key in base_files:
        image_file_objects[base_file_key].__class__ = ImageFile.ImageFile
        image_file_objects[base_file_key].init_imageFile()

    return image_file_objects
