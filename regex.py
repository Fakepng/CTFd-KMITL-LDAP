import re

def format_curriculum(text):
    match = re.match(r"^Bachelor of.*?(?:(\()| in )(.*)", text)

    if match:
        was_separated_by_paren = match.group(1)
        cleaned = match.group(2)

        # 1. ONLY remove a trailing ')' if it was separated by a parenthesis
        # AND if there is an extra unmatched closing parenthesis.
        if was_separated_by_paren:
            if cleaned.endswith(")") and cleaned.count(")") > cleaned.count("("):
                cleaned = cleaned.rstrip(")")

        # 2. NEW RULE: Check if it's an Engineering degree but "Engineering" is missing from the cleaned name
        # (We check for 'Efngineering' just to safely catch that typo in your data!)
        if re.search(r"engineering", text, re.IGNORECASE) or "Efngineering" in text:
            if "Engineering" not in cleaned:
                # Smart insert: If there is a trailing parenthesis tag, put "Engineering" BEFORE it.
                # Otherwise, just add it to the end.
                paren_match = re.search(r"(\s*\(.*\))$", cleaned)
                if paren_match:
                    cleaned = cleaned[:paren_match.start()] + " Engineering" + paren_match.group(1)
                else:
                    cleaned += " Engineering"

        return cleaned

    return text

# --- Testing your data ---
data_list = [
    "Bachelor of Engineering and Bachelor of Science (IoT System Information Engineering and Industrial Physics (Dual Degree)",
    "Bachelor of Engineering Program in IoTSystem and Information Engineering",
    "Bachelor of Engineering (Mechatronics and Automation Engineering)",
    "Bachelor of Engineering Program in Food Engineering",
    "Bachelor of Engineering Program in Electronics",
    "Bachelor of Engineering Programme in Electrical Engineering",
    "Bachelor of Engineering Program in Industrial Engineering",
    "Bachelor of Efngineering Program in Chemical Engineering",
    "Bachelor of Engineering Program in Agro-Industrial Systems Engineering",
    "Bachelor of Engineering in Communications and Electronics Engineering (Continuing Program)",
    "Bachelor of Engineering in Industrial Engineering and Logistics Management (International Program)"
]

for item in data_list:
    print(f"Cleaned: {format_curriculum(item)}")