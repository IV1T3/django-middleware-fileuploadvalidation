import os
import logging
import time

from datetime import datetime

def create_file_path(filename):
    logging.debug("[Reporter module] - Creating file path")
    curr_time = time.time()
    report_name = filename + "_" + str(curr_time) + ".log"
    file_path = f"./uploadlogs/{report_name}"
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    return file_path


def build_report(files):
    logging.debug("[Reporter module] - Building report")
    for _, file in files.items():
        now = datetime.now().strftime("%d. %B %Y - %H:%M:%S")
        file_path = create_file_path(file.basic_information.name)
        with open(file_path, "w+") as report:
            report.write("File Upload Report\n")
            report.write("Upload date and time: " + now + " UTC\n")
            #######################
            ## Basic Information ##
            #######################
            report.write("================================\n")
            report.write("Basic file information\n")
            report.write("--------------------------------\n")
            report.write("File name:" + str(file.basic_information.name) + "\n")
            report.write("File size:" + str(file.basic_information.size) + "\n")
            report.write(
                "Content-Type:" + str(file.basic_information.content_type) + "\n"
            )
            report.write(
                "Content-Type Extra:"
                + str(file.basic_information.content_type_extra)
                + "\n"
            )
            report.write("Charset:" + str(file.basic_information.charset) + "\n")
            report.write("MD5:" + str(file.basic_information.md5) + "\n")
            report.write("SHA-1:" + str(file.basic_information.sha1) + "\n")
            report.write("SHA-256:" + str(file.basic_information.sha256) + "\n")
            report.write("Filename length:" + str(file.basic_information.filename_length) + "\n")
            report.write("Block:" + str(file.block) + "\n")
            report.write("Block reasons:" + str(file.block_reasons) + "\n")
            #######################
            ## Detection Results ##
            #######################
            report.write("================================\n")
            report.write("Detection Results\n")
            report.write("--------------------------------\n")
            report.write("File integrity:" + str(file.detection_results.file_integrity) + "\n")
            report.write("Filename splits:" + str(file.detection_results.filename_splits) + "\n")
            report.write("Extensions:" + str(file.detection_results.extensions) + "\n")
            report.write("Signature MIME:" + str(file.detection_results.signature_mime) + "\n")
            report.write("Guessed MIME:" + str(file.detection_results.guessed_mime) + "\n")

            ########################
            ## Validation Results ##
            ########################
            report.write("================================\n")
            report.write("Validation Results\n")
            report.write("--------------------------------\n")
            report.write("file_size_ok:" + str(file.validation_results.file_size_ok) + "\n")
            report.write("request_mime_ok:" + str(file.validation_results.request_mime_ok) + "\n")
            report.write("signature_mime_ok:" + str(file.validation_results.signature_mime_ok) + "\n")
            report.write("matching_extension_signature_request_ok:" + str(file.validation_results.matching_extension_signature_request_ok) + "\n")
            report.write("filename_length_ok:" + str(file.validation_results.filename_length_ok) + "\n")
            report.write("extensions_whitelist_ok:" + str(file.validation_results.extensions_whitelist_ok) + "\n")
            report.write("request_whitelist_ok:" + str(file.validation_results.request_whitelist_ok) + "\n")
            report.write("signature_whitelist_ok:" + str(file.validation_results.signature_whitelist_ok) + "\n")
            report.write("malicious:" + str(file.validation_results.malicious) + "\n")

            ######################
            ## Possible Attacks ##
            ######################
            report.write("================================\n")
            report.write("Possible Attacks\n")
            report.write("--------------------------------\n")
            report.write("mime_manipulation:" + str(file.attack_results.mime_manipulation) + "\n")
            report.write("null_byte_injection:" + str(file.attack_results.null_byte_injection) + "\n")
            report.write("exif_injection:" + str(file.attack_results.exif_injection) + "\n")

            ##########################
            ## Sanitization Results ##
            ##########################
            report.write("================================\n")
            report.write("Sanitization Results\n")
            report.write("--------------------------------\n")
            report.write("cleansed_exif:" + str(file.sanitization_results.cleansed_exif) + "\n")
            report.write("cleansed_structure:" + str(file.sanitization_results.cleansed_structure) + "\n")
            report.write("created_random_filename_with_guessed_extension:" + str(file.sanitization_results.created_random_filename_with_guessed_extension) + "\n")
            report.write("================================\n")
