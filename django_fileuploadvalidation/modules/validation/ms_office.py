import logging

from oletools.olevba import VBA_Parser
from oletools import mraptor


def check_vba_macros(file):
    logging.debug("[Validation module] - CHECK: VBA macros - STARTED")
    vba_parser = VBA_Parser(file.basic_information.name, data=file.content)

    malicious_indicators = {
        "AutoExec": [],
        "Suspicious": [],
        "IOC": [],
        "Hex String": [],
        "Base64 String": [],
        "Dridex String": [],
        "VBA String": [],
        "MacroRaptor": [],
    }

    macros_found = vba_parser.detect_macros()
    if macros_found:

        # Iterating all indicators according to:
        # https://github.com/decalage2/oletools/blob/08056c175b3b3bb2a0271f1c9601c0c9e47ad1b8/oletools/olevba.py

        macro_analysis_results = vba_parser.analyze_macros(show_decoded_strings=True)
        for key_type, key_value, desc in macro_analysis_results:
            malicious_indicators[key_type].append([key_value, desc])

        # Analyzing macros with MacroRaptor
        vba_code_all_modules = ""
        for (_, _, _, vba_code_single_module) in vba_parser.extract_all_macros():
            vba_code_all_modules += vba_code_single_module + "\n"

        mraptor_obj = mraptor.MacroRaptor(vba_code_all_modules)
        mraptor_obj.scan()

        mraptor_indicators = []

        if mraptor_obj.matches:
            mraptor_indicators = mraptor_obj.matches

        malicious_indicators["MacroRaptor"] = mraptor_indicators

    return macros_found, malicious_indicators
