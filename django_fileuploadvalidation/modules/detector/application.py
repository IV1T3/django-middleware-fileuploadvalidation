import logging


def check_pdf_for_data_after_EOD(file_object, detection_data):
    logging.info("[PDF Detector module] - Starting to check PDF for data after EOD")

    # Check PDF for extra data after EOD marker

    return detection_data


def run_pdf_detection(pdf_file_objects, pdf_detection_data):
    logging.info("[PDF Detector module] - Starting PDF detection")

    for file_obj_key, file_obj in pdf_file_objects.items():

        pdf_detection_data = pdf_detection_data[file_obj_key]

        # read bytes of PDF file
        pdf_bytes = file_obj.read()
        print(pdf_bytes)

        # Invalid PDF section
        # Check PDF for sections that are neither a comment nor body, cross-reference table, or trailer

        # Check PDF for unreferenced objects

        # Check PDF for extra data after EOD marker

        pdf_detection_data = check_pdf_for_data_after_EOD(file_obj, pdf_detection_data)

    return pdf_detection_data
