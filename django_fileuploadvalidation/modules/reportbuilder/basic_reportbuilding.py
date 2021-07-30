import os
import logging

from datetime import datetime


def run_reportbuilder(file_objects, detection_data, sanitized_data=None):
    logging.info("[ReportBuilder module] - Building report")
    for key in file_objects:
        now = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        file_data = file_objects[key].file_data
        report_name = file_data["name"] + ".log"
        file_path = f"./uploadlogs/{report_name}"
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w+") as report:
            report.write("File Upload Report\n")
            report.write("Upload date and time: " + now + "\n")
            report.write("================================\n")
            report.write("File object data\n")
            report.write("--------------------------------\n")
            report.write("File name:" + str(file_data["name"]) + "\n")
            report.write("File size:" + str(file_data["size"]) + "\n")
            report.write("Content-Type:" + str(file_data["content_type"]) + "\n")
            report.write(
                "Content-Type Extra:" + str(file_data["content_type_extra"]) + "\n"
            )
            report.write("Charset:" + str(file_data["charset"]) + "\n")
            # report.write("EXIF:" + str(file_data["exif_data"]) + "\n")
            report.write("================================\n")
            report.write("Detection data\n")
            report.write("--------------------------------\n")
            report.write("Block:" + str(detection_data[key]["file"]["block"]) + "\n")
            report.write(
                "Block reasons:"
                + str(detection_data[key]["file"]["block_reasons"])
                + "\n"
            )
            report.write(
                "guessed_mime:"
                + str(detection_data[key]["file"]["guessed_mime"])
                + "\n"
            )
            report.write(
                "guessed_mime:"
                + str(detection_data[key]["file"]["guessed_mime"])
                + "\n"
            )
            report.write(
                "Malicious:" + str(detection_data[key]["file"]["malicious"]) + "\n"
            )
            report.write(
                "request_header_mime:"
                + str(detection_data[key]["file"]["request_header_mime"])
                + "\n"
            )
            report.write(
                "signature_mime:"
                + str(detection_data[key]["file"]["signature_mime"])
                + "\n"
            )
            report.write("size:" + str(detection_data[key]["file"]["size"]) + "\n")
            report.write("================================\n")
            if sanitized_data:
                report.write("Sanitization data\n")
                report.write("--------------------------------\n")
                report.write(
                    "cleansed_structure:"
                    + str(sanitized_data[key]["cleansed_structure"])
                    + "\n"
                )
                report.write("================================\n")
