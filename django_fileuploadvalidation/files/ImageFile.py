from io import BytesIO

import logging
import exifread

from . import BaseFile


class ImageFile(BaseFile.BaseFile):
    """
    A class to store image file information.
    """

    def __init__(self, file):
        super().__init__(file)
    
    def init_imageFile(self):
        self._exif_data = self._retrieve_exif_data()

    @property
    def exif_data(self):
        logging.info("[ImageFile class] - Getting file exif data")
        return self._exif_data

    @exif_data.setter
    def exif_data(self, new_exif_data):
        logging.info("[ImageFile class] - Setting new exif data")
        self._exif_data = new_exif_data

    def _retrieve_exif_data(self):
        logging.info("[ImageFile class] - Retrieving file exif data")
        file_bytes_buffer = BytesIO(self._content)
        exif_data = exifread.process_file(file_bytes_buffer, details=False)
        return exif_data