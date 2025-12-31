import xmltodict
import json


XML_FILE = "./original/xml/CE01.xml"
OUTPUT_JSON = "./original/json/CE01.json"

with open(XML_FILE, "r", encoding="utf-8") as f:
    xml_data = f.read()

dict_data = xmltodict.parse(xml_data)

with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(dict_data, f, ensure_ascii=False, indent=2)