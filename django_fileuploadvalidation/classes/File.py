from io import BytesIO

import exifread
import logging


class File:
    """
    Common base class for all files.
    """

    def __init__(self, file):
        logging.info("[File class] - Initializing file object")
        self._uploaded_file = file
        self._name = file.name
        self._size = file.size
        self._content_type = file.content_type
        self._content_type_extra = file.content_type_extra
        self._charset = file.charset
        self._content = b"".join([chunk for chunk in file.chunks()])
        self._exif_data = self._retrieve_exif_data()
        self._block = False

    def _retrieve_exif_data(self):
        logging.info("[File class] - Retrieving file exif data")
        file_bytes_buffer = BytesIO(self._content)
        exif_data = exifread.process_file(file_bytes_buffer, details=False)
        return exif_data

    @property
    def block(self):
        logging.info("[File class] - Getting block status")
        return self._block

    @block.setter
    def block(self, new_block_status):
        logging.info("[File class] - Setting new block status")
        self._block = new_block_status

    @property
    def content(self):
        logging.info("[File class] - Getting file content")
        return self._content

    @content.setter
    def content(self, new_content):
        logging.info("[File class] - Setting new file content")
        self._content = new_content

    @property
    def content_type(self):
        logging.info("[File class] - Getting file content type")
        return self._content_type

    @property
    def exif_data(self):
        logging.info("[File class] - Getting file exif data")
        return self._exif_data

    @exif_data.setter
    def exif_data(self, new_exif_data):
        logging.info("[File class] - Setting new exif data")
        self._exif_data = new_exif_data

    @property
    def file_data(self):
        logging.info("[File class] - Getting complete file data")
        file_information = {
            "name": self._name,
            "size": self._size,
            "content_type": self._content_type,
            "content_type_extra": self._content_type_extra,
            "charset": self._charset,
            "content": self._content,
            "exif_data": self._exif_data,
        }
        return file_information

    @property
    def name(self):
        logging.info("[File class] - Getting file name")
        return self._name

    @name.setter
    def name(self, new_name):
        logging.info("[File class] - Setting new file name")
        self._name = new_name

    @property
    def size(self):
        logging.info("[File class] - Getting file size")
        return self._size
