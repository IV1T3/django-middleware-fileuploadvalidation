import exifread
import hashlib
import logging

from dataclasses import dataclass, field
from io import BytesIO


@dataclass
class BasicFileInformation:
    name: str
    size: int
    content_type: str
    content_type_extra: str
    charset: str
    md5: str
    sha1: str
    sha256: str
    exif_data: dict = field(default_factory=dict)
    filename_length: int = 0


@dataclass
class DetectionResults:
    filename_splits: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    signature_mime: str = ""


@dataclass
class ValidationResults:
    file_size_ok: bool = False


@dataclass
class PossibleAttacks:
    file_size_too_big: bool = False


@dataclass
class SanitizationResults:
    cleansed_exif: bool = False
    cleansed_structure: bool = False
    created_random_filename_with_guessed_extension: bool = False


class BaseFile:
    """
    Common base class for all files.
    """

    def __init__(self, file):
        logging.info("[File class] - Initializing file object")
        self._uploaded_file = file
        # self._name = file.name
        # self._size = file.size
        # self._content_type = file.content_type
        # self._content_type_extra = file.content_type_extra
        # self._charset = file.charset
        self._content = b"".join([chunk for chunk in file.chunks()])
        self._block = False
        self._block_reasons = []

        hash_md5, hash_sha1, hash_sha256 = self._get_file_hashes()
        exif_data = self._retrieve_exif_data()

        self.basic_information = BasicFileInformation(
            file.name,
            file.size,
            file.content_type,
            file.content_type_extra,
            file.charset,
            hash_md5,
            hash_sha1,
            hash_sha256,
            exif_data,
        )

        self.validation_results = ValidationResults()
        self.attack_results = PossibleAttacks()
        self.detection_results = DetectionResults()
        self.sanitization_results = SanitizationResults()

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

    def _retrieve_exif_data(self):
        logging.info("[File class] - Retrieving file exif data")
        file_bytes_buffer = BytesIO(self._content)
        exif_data = exifread.process_file(file_bytes_buffer, details=False)
        return exif_data

    @property
    def uploaded_file(self):
        logging.info("[File class] - Getting uploaded file")
        return self._uploaded_file

    # @property
    # def name(self):
    #     logging.info("[File class] - Getting file name")
    #     return self._name

    # @property
    # def size(self):
    #     logging.info("[File class] - Getting file size")
    #     return self._size

    # @property
    # def content_type(self):
    #     logging.info("[File class] - Getting file content type")
    #     return self._content_type

    # @property
    # def content_type_extra(self):
    #     logging.info("[File class] - Getting file content type extra")
    #     return self._content_type_extra

    # @property
    # def charset(self):
    #     logging.info("[File class] - Getting file charset")
    #     return self._charset

    @property
    def content(self):
        logging.info("[File class] - Getting file content")
        return self._content

    @property
    def block(self):
        logging.info("[File class] - Getting block status")
        return self._block

    # @property
    # def file_data(self):
    #     logging.info("[File class] - Getting complete file data")
    #     file_information = {
    #         "name": self._name,
    #         "size": self._size,
    #         "content_type": self._content_type,
    #         "content_type_extra": self._content_type_extra,
    #         "charset": self._charset,
    #         "content": self._content,
    #         "hash_md5": self._hash_md5,
    #         "hash_sha1": self._hash_sha1,
    #         "hash_sha256": self._hash_sha256,
    #     }
    #     return file_information

    # @name.setter
    # def name(self, new_name):
    #     logging.info("[File class] - Setting new file name")
    #     self._name = new_name

    @content.setter
    def content(self, new_content):
        logging.info("[File class] - Setting new file content")
        self._content = new_content

    @block.setter
    def block(self, new_block_status):
        logging.info("[File class] - Setting new block status")
        self._block = new_block_status
