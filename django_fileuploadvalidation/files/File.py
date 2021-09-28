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
    file_integrity: bool = False
    filename_splits: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    signature_mime: str = ""
    guessed_mime: str = ""


@dataclass
class ValidationResults:
    file_size_ok: bool = False
    request_mime_ok: bool = False
    signature_mime_ok: bool = False
    matching_extension_signature_request_ok: bool = False
    filename_length_ok: bool = False
    extensions_whitelist_ok: bool = False
    request_whitelist_ok: bool = False
    signature_whitelist_ok: bool = False
    malicious: bool = False


@dataclass
class PossibleAttacks:
    mime_manipulation: bool = False
    null_byte_injection: bool = False
    exif_injection: bool = False


@dataclass
class SanitizationResults:
    cleansed_exif: bool = False
    cleansed_structure: bool = False
    created_random_filename_with_guessed_extension: bool = False


class File:
    """
    Common class for all files.
    """

    def __init__(self, file):
        logging.info("[File class] - Initializing file object")
        self._uploaded_file = file
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

    @property
    def content(self):
        logging.info("[File class] - Getting file content")
        return self._content

    @property
    def block(self):
        logging.info("[File class] - Getting block status")
        return self._block

    @property
    def block_reasons(self):
        logging.info("[File class] - Getting block reasons")
        return self._block_reasons

    @content.setter
    def content(self, new_content):
        logging.info("[File class] - Setting new file content")
        self._content = new_content

    @block.setter
    def block(self, new_block_status):
        logging.info("[File class] - Setting new block status")
        self._block = new_block_status

    def append_block_reason(self, block_reason):
        logging.info("[File class] - Appending new block reason")
        self._block_reasons.append(block_reason)
