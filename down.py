#!/usr/bin/env python3

import re
import requests
from bs4 import BeautifulSoup


r = requests.get("https://craigwrightisnotsatoshi.com")
soup = BeautifulSoup(r.text, "html.parser")

pre = soup.find("pre")

pattern = re.compile(
    pattern=r"^(?P<address>[13][a-zA-Z0-9]{25,34})\s+(?P<signature>[+\w/=]+)$",
    flags=re.MULTILINE,
)

matches = pattern.finditer(pre.get_text())
for match in matches:
    addr = match.group("address")
    sig = match.group("signature")
    print(f"{addr} {sig}")
