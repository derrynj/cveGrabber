import requests
import logging
import yaml
from cveGrabber import cve_matches_products, load_config

# Setup basic logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TARGET_CVE = "CVE-2025-40601"

def check_specific_cve():
    logging.info(f"Fetching details for {TARGET_CVE}...")
    
    config = load_config()
    products = config["filters"]["products"]
    logging.info(f"Loaded {len(products)} product filters from config.yaml")
    
    params = {
        "cveId": TARGET_CVE
    }
    
    try:
        response = requests.get(NVD_API, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            logging.error(f"❌ CVE {TARGET_CVE} not found in NVD API!")
            return

        cve = vulns[0]["cve"]
        logging.info(f"✅ Found {TARGET_CVE}")
        
        # Check description
        desc = cve.get("descriptions", [{}])[0].get("value", "No description")
        logging.info(f"   Description: {desc}")
        
        # Run the match logic
        logging.info("   Running match logic...")
        match = cve_matches_products(cve, products)
        
        if match:
            logging.info(f"✅ MATCHED! Vendor: {match}")
        else:
            logging.error("❌ DID NOT MATCH any filter.")
            
            # Debug why
            logging.info("   Debugging filters:")
            for p in products:
                if p["vendor"].lower() == "sonicwall":
                    logging.info(f"      Checking against SonicWall filter: {p}")
                    if "sonicwall" in desc.lower():
                         logging.info("      'sonicwall' found in description.")
                    else:
                         logging.info("      'sonicwall' NOT found in description.")
                    
                    prod = p["product"]
                    if "sonicos" in desc.lower():
                        logging.info(f"      'sonicos' found in description.")
                    else:
                        logging.info(f"      'sonicos' NOT found in description.")

    except Exception as e:
        logging.error(f"Error: {e}")

if __name__ == "__main__":
    check_specific_cve()
