import xmltodict
import json

with open("input.xml", "r", encoding="utf-8") as f:
    xml_data = f.read()

dict_data = xmltodict.parse(xml_data)

with open("output.json", "w", encoding="utf-8") as f:
    json.dump(dict_data, f, ensure_ascii=False, indent=2)