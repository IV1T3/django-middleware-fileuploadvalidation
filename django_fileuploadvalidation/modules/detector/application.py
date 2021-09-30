import logging
import PyPDF2
import io


# def check_pdf_for_data_after_EOD(file_object):
#     logging.debug("[PDF Detector module] - Starting to check PDF for data after EOD")

#     # Check PDF for extra data after EOD marker

#     return detection_data


def check_pdf_integrity(file):
    try:
        pdf_buff = io.BytesIO(file.content)
        pdf_obj = PyPDF2.PdfFileReader(pdf_buff)
        pdf_obj.getDocumentInfo()
    except Exception as e:
        return False

    return True


def detect_file(file):
    logging.debug("[Detector module] - Starting application detection")

    if file.detection_results.guessed_mime == "application/pdf":
        file.detection_results.file_integrity = check_pdf_integrity(file)

    return file


# def run_pdf_detection(pdf_file_objects):
#     logging.debug("[PDF Detector module] - Starting PDF detection")

#     for file_obj_key, file_obj in pdf_file_objects.items():

#         pdf_detection_data = pdf_detection_data[file_obj_key]

#         # read bytes of PDF file
#         pdf_bytes = file_obj.read()
#         print(pdf_bytes)

#         # Invalid PDF section
#         # Check PDF for sections that are neither a comment nor body, cross-reference table, or trailer

#         # Check PDF for unreferenced objects

#         # Check PDF for extra data after EOD marker

#         # pdf_detection_data = check_pdf_for_data_after_EOD(file_obj)

#     return pdf_detection_data
