import os
import logging

from datetime import datetime


def build_report(file_objects, sanitized_data=None):
    logging.info("[ReportBuilder module] - Building report")
    for file_obj_key, file_obj in file_objects.items():
        now = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        report_name = file_obj.basic_information.name + ".log"
        file_path = f"./uploadlogs/{report_name}"
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w+") as report:
            report.write("File Upload Report\n")
            report.write("Upload date and time: " + now + "\n")
            report.write("================================\n")
            report.write("File object data\n")
            report.write("--------------------------------\n")
            report.write("File name:" + str(file_obj.basic_information.name) + "\n")
            report.write("File size:" + str(file_obj.basic_information.size) + "\n")
            report.write(
                "Content-Type:" + str(file_obj.basic_information.content_type) + "\n"
            )
            report.write(
                "Content-Type Extra:"
                + str(file_obj.basic_information.content_type_extra)
                + "\n"
            )
            report.write("Charset:" + str(file_obj.basic_information.charset) + "\n")
            # report.write("EXIF:" + str(file_data["exif_data"]) + "\n")
            report.write("================================\n")
            report.write("Detection data\n")
            report.write("--------------------------------\n")
            report.write("Block:" + str(file_obj.block) + "\n")
            report.write("Block reasons:" + str(file_obj.block_reasons) + "\n")
            report.write(
                "guessed_mime:" + str(file_obj.detection_results.guessed_mime) + "\n"
            )
            report.write(
                "Malicious:" + str(file_obj.validation_results.malicious) + "\n"
            )
            report.write(
                "signature_mime:"
                + str(file_obj.detection_results.signature_mime)
                + "\n"
            )
            report.write("================================\n")
            if sanitized_data:
                report.write("Sanitization data\n")
                report.write("--------------------------------\n")
                report.write("================================\n")
