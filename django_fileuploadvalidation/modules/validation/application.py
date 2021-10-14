import logging
import PyPDF2
import io
import pprint
import yaml

from pathlib import Path

from pdfid import pdfid

from . import ms_office

pp = pprint.PrettyPrinter(indent=4)

from django.conf import settings


def check_pdf_integrity(file):
    pdf_buff = io.BytesIO(file.content)
    try:
        pdf_obj = PyPDF2.PdfFileReader(pdf_buff)
        pdf_obj.getDocumentInfo()
    except Exception as e:
        logging.warning(f"[Validation module] - CHECK: PDF integrity (1) - FAILED: {e}")
        return False

    logging.debug("[Validation module] - CHECK: PDF integrity - PASSED")
    return True


def get_pdfid_information(file):

    file_buffers = [file.content]

    options = pdfid.get_fake_options()
    options.json = True

    list_of_dict = pdfid.PDFiDMain(["analyzing.pdf"], options, file_buffers)["reports"][
        0
    ]

    pp.pprint(list_of_dict)

    return list_of_dict


def is_pdf_malicious(pdfid_data):
    """
    Takes a look at various PDFiD data points and calculates
    whether the PDF is malicious.
    """

    # The lower the better
    score = 0
    js_included = False
    automatic_action = False
    malicious_reasons = []

    # 1. Most malicious PDF document have only one page.
    if pdfid_data["/Page"] == 1:
        score += 1
        malicious_reasons.append("PDF_only_one_page")

    # 2. Almost all malicious PDF documents that I’ve found in the wild contain
    # JavaScript (to exploit a JavaScript vulnerability and/or to execute a heap spray)
    if pdfid_data["/JS"] > 0 or pdfid_data["/JavaScript"] > 0:
        score += 1
        js_included = True
        malicious_reasons.append("PDF_js_included")

    # 3. All malicious PDF documents with JavaScript I’ve seen in the wild had
    # an automatic action to launch the JavaScript without user interaction.
    if pdfid_data["/AA"] > 0 or pdfid_data["/OpenAction"] > 0:
        score += 1
        automatic_action = True
        malicious_reasons.append("PDF_automatic_action")

    if js_included and automatic_action:
        score += 5
        malicious_reasons.append("PDF_js_and_automatic_action")

    # 4. JBIG2 compression is not necessarily and indication of a malicious
    # PDF document, but requires further investigation.
    if pdfid_data["/JBIG2Decode"] > 0:
        score += 1
        malicious_reasons.append("PDF_jbig2_compression")

    if score <= 2:
        logging.debug("[Validation module] - CHECK: PDF maliciousness - PASSED")
    else:
        logging.warning(
            "[Validation module] - CHECK: PDF maliciousness - FAILED: "
            + ", ".join(malicious_reasons)
        )

    return score > 2, malicious_reasons


def validate_file(file):
    logging.debug("[Validation module] - Starting application detection")

    is_pdf = file.detection_results.guessed_mime == "application/pdf"

    office_yaml_path = Path(__file__).parent.parent.parent / "data" / "office_mimes.yml"

    with open(office_yaml_path, "r") as stream:
        office_mimes = yaml.safe_load(stream)

    is_office_doc = file.detection_results.guessed_mime in office_mimes

    if is_pdf:
        logging.debug("[Validation module] - is_pdf")
        file.validation_results.file_integrity_ok = check_pdf_integrity(file)
        file.validation_results.file_integrity_check_done = True

        if not file.validation_results.file_integrity_ok:
            logging.warning(f"[Validation module] - PDF file integrity check FAILED")

        pdfid_data = get_pdfid_information(file)
        pdf_malicious, malicious_reasons = is_pdf_malicious(pdfid_data)

        file.detection_results.found_pdf_malicious_reasons = malicious_reasons

        file.validation_results.pdf_malicious_check_ok = not pdf_malicious
        file.validation_results.pdf_malicious_check_done = True

        if pdf_malicious:
            logging.warning(
                f"[Validation module] - PDF malicious check FAILED: {malicious_reasons}"
            )

    if is_office_doc:
        logging.debug("[Validation module] - is_office_doc")
        macros_found, malicious_indicators = ms_office.check_vba_macros(file)
        file.validation_results.office_macros_ok = not macros_found

        print(f"{macros_found=}")
        pp.pprint(malicious_indicators)

        if macros_found:
            logging.warning(
                f"[Validation module] - Office malicious check FAILED: {malicious_indicators}"
            )

    logging.debug("[Validation module] - Detection: Application - DONE")

    return file
