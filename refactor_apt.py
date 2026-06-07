import os, re
base_dir = r"C:\Users\test\Downloads\SUMIT PROJECT\Unified_Security_Hub\frontend\templates\dark_web_views"

def fix_dash():
    path = os.path.join(base_dir, "apt_dashboard.html")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    # Extracting core parts from apt_dashboard
    content = re.search(r'<!-- Dashboard Content -->(.*?)<!-- Screenshot Modal -->', text, re.DOTALL)
    modal = re.search(r'<!-- Screenshot Modal -->(.*?)<script>', text, re.DOTALL)
    script = re.search(r'<script>(.*?)</script>\s*</body>', text, re.DOTALL)

    out = '{% extends "layout.html" %}\n{% block content %}\n'
    if content: out += content.group(1)
    if modal: out += '<!-- Screenshot Modal -->' + modal.group(1)
    out += '{% endblock %}\n{% block scripts %}\n<script>\n'
    if script: out += script.group(1)
    out += '\n</script>\n{% endblock %}'

    with open(path, "w", encoding="utf-8") as f: f.write(out)

def fix_profile():
    path = os.path.join(base_dir, "apt_profile.html")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    content = re.search(r'<!-- Dashboard Content -->(.*?)<script>', text, re.DOTALL)
    script = re.search(r'<script>(.*?)</script>\s*</body>', text, re.DOTALL)

    out = '{% extends "layout.html" %}\n{% block content %}\n'
    if content: out += content.group(1)
    out += '{% endblock %}\n{% block scripts %}\n<script>\n'
    if script: out += script.group(1)
    out += '\n</script>\n{% endblock %}'

    with open(path, "w", encoding="utf-8") as f: f.write(out)

fix_dash()
fix_profile()
print("Templates refactored successfully.")
