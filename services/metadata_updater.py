# da runnare IN QUESTA CARTELLA services/ -> risolvi
# risolvi anche il os.getenv (obiettivo: settings da .env)

import json
import requests

# URL of the registry SPID
registry_url = "https://registry.spid.gov.it/entities-idp?&output=json"

# Name of the output JSON file
output_file = "../spid/static/idps_map.json"  #/spid/static/idps_map.json

# Download the JSON directly from the site
response = requests.get(registry_url)
response.raise_for_status()  # raise an error if the download fails
data = response.json()

# Transform the JSON
result = {}
for item in data:
    entity_id = item.get("entity_id")
    if entity_id:
        result[entity_id] = {
            "signing_certificate_x509": item.get("signing_certificate_x509", []),
            "single_logout_service": item.get("single_logout_service", []),
            "single_sign_on_service": item.get("single_sign_on_service", [])
        }

# Save the transformed JSON
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print(f"Transformed JSON saved in {output_file}")