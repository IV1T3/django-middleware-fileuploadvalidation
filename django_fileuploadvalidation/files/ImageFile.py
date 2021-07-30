from io import BytesIO

import logging
import exifread

import BaseFile


class ImageFile(BaseFile.BaseFile):
    """
    A class to store image file information.
    """

    def __init__(self, file):
        super().__init__(file)
        self._exif_data = self._retrieve_exif_data()

    def _retrieve_exif_data(self):
        logging.info("[ImageFile class] - Retrieving file exif data")
        file_bytes_buffer = BytesIO(self._content)
        exif_data = exifread.process_file(file_bytes_buffer, details=False)
        return exif_data