import logging

from datetime import datetime


def run_reportbuilder(sanitized_file_objects, detection_data, sanitized_data):
    logging.info("[ReportBuilder module] - Building report")
    for key in sanitized_file_objects:
        now = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        report_name = sanitized_file_objects[key].name + ".log"
        with open("uploadlogs/" + report_name, "w+") as report:
            report.write("File Upload Report\n")
            report.write("Upload date and time: " + now + "\n")
            report.write("---------------\n")
            report.write("---------------\n")
            report.write("Detection data\n")
            report.write(
                "Malicious:" + str(detection_data[key]["file"]["malicious"]) + "\n"
            )
            report.write("------\n")
            report.write("Sanitization data\n")
            report.write(
                "cleansed_structure:"
                + str(sanitized_data[key]["cleansed_structure"])
                + "\n"
            )
