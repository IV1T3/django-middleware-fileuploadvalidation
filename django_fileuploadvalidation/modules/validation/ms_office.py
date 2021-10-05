import logging

from oletools.olevba import VBA_Parser
from oletools import mraptor


def check_vba_macros(file):
    logging.debug("[Validation module] - CHECK: VBA macros - STARTED")
    vba_parser = VBA_Parser(file.basic_information.name, data=file.content)

    malicious_indicators = {
        "AutoExec": [],
        "IOC": [],
        "Hex String": [],
        "Base64 String": [],
        "AutoExec": [],
        "Suspicious": [],
        "Dridex String": [],
        "MacroRaptor": [],
        "nb_counts": {
            "AutoExec": 0,
            "Suspicious": 0,
            "IOC": 0,
            "Hex String": 0,
            "Base64 String": 0,
            "Dridex String": 0,
            "VBA String": 0,
        },
    }

    macros_found = vba_parser.detect_macros()
    if macros_found:

        macro_analysis_results = vba_parser.analyze_macros(show_decoded_strings=True)
        for key_type, key_value, desc in macro_analysis_results:
            malicious_indicators[key_type].append([key_value, desc])

        # Iterating all indicators according to:
        # https://github.com/decalage2/oletools/blob/08056c175b3b3bb2a0271f1c9601c0c9e47ad1b8/oletools/olevba.py

        # AutoExec keywords
        if vba_parser.nb_autoexec > 0:
            malicious_indicators["nb_counts"]["AutoExec"] = vba_parser.nb_autoexec

        # Suspicious keywords
        if vba_parser.nb_suspicious > 0:
            malicious_indicators["nb_counts"]["Suspicious"] = vba_parser.nb_suspicious

        # Indicator of Compromise
        if vba_parser.nb_iocs > 0:
            malicious_indicators["nb_counts"]["IOC"] = vba_parser.nb_iocs

        # Hex obfuscated strings
        if vba_parser.nb_hexstrings > 0:
            malicious_indicators["nb_counts"]["Hex String"] = vba_parser.nb_hexstrings

        # Base64 obfuscated strings
        if vba_parser.nb_base64strings > 0:
            malicious_indicators["nb_counts"][
                "Base64 String"
            ] = vba_parser.nb_base64strings

        # Dridex obfuscated strings
        if vba_parser.nb_dridexstrings > 0:
            malicious_indicators["nb_counts"][
                "Dridex String"
            ] = vba_parser.nb_dridexstrings

        # VBA obfuscated strings
        if vba_parser.nb_vbastrings > 0:
            malicious_indicators["nb_counts"]["VBA String"] = vba_parser.nb_vbastrings

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
