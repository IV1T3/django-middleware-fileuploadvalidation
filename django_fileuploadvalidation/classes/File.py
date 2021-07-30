from io import BytesIO

import exifread
import hashlib
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

        self._hash_md5, self._hash_sha1, self._hash_sha256 = self._get_file_hashes()

    def _retrieve_exif_data(self):
        logging.info("[File class] - Retrieving file exif data")
        file_bytes_buffer = BytesIO(self._content)
        exif_data = exifread.process_file(file_bytes_buffer, details=False)
        return exif_data

    def _get_file_hashes(self):
        logging.info("[File class] - Retrieving file hashes")
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        for chunk in self._uploaded_file.chunks():
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

        hexdigest_md5 = md5_hash.hexdigest()
        hexdigest_sha1 = sha1_hash.hexdigest()
        hexdigest_sha256 = sha256_hash.hexdigest()

        logging.info(f"[File class] - MD5: {hexdigest_md5}")
        logging.info(f"[File class] - SHA1: {hexdigest_sha1}")
        logging.info(f"[File class] - SHA256: {hexdigest_sha256}")

        return hexdigest_md5, hexdigest_sha1, hexdigest_sha256

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
            "hash_md5": self._hash_md5,
            "hash_sha1": self._hash_sha1,
            "hash_sha256": self._hash_sha256,
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
