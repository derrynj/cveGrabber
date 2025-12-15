import requests
import smtplib
import yaml
import argparse
import logging
import os
import re
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from difflib import get_close_matches
script_dir = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(script_dir, "config.yaml")
STATE_FILE_DIGEST = Path(os.path.join(script_dir, "seen_cves_digest.txt"))
STATE_FILE_REALTIME = Path(os.path.join(script_dir, "seen_cves_realtime.txt"))
ERROR_STATE_FILE = Path(os.path.join(script_dir, "error_report_state.txt"))
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

log_warnings = []  # track runtime/logging warnings
metrics = {"cves_found": 0, "cves_sent": 0, "cves_skipped": 0}


# ---------------- Logging Setup ----------------
def setup_logging(config):
    log_cfg = config.get("logging", {})
    log_file = log_cfg.get("log_file", "cve_alert.log")
    if not os.path.isabs(log_file):
        log_file = os.path.join(script_dir, log_file)
    log_level = log_cfg.get("log_level", "INFO").upper()
    rotation = log_cfg.get("rotation", "daily")
    backup_count = log_cfg.get("backup_count", 7)
    max_size_mb = log_cfg.get("max_size_mb", 5)

    handlers = []
    try:
        log_dir = Path(log_file).parent
        if not log_dir.exists() or not log_dir.is_dir() or not os.access(log_dir, os.W_OK):
            raise PermissionError(f"Log directory '{log_dir}' not writable.")

        if rotation == "daily":
            file_handler = TimedRotatingFileHandler(log_file, when="midnight", backupCount=backup_count)
        elif rotation == "size":
            file_handler = RotatingFileHandler(log_file, maxBytes=max_size_mb*1024*1024, backupCount=backup_count)
        else:
            file_handler = logging.FileHandler(log_file)

        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        handlers.append(file_handler)
    except Exception as e:
        msg = f"⚠️ Logging fallback: {e}"
        log_warnings.append(msg)
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            handlers=[logging.StreamHandler()]
        )
        logging.error(msg)
        return

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    handlers.append(console_handler)

    logging.basicConfig(level=getattr(logging, log_level, logging.INFO), handlers=handlers)


# ---------------- Config & State ----------------
def load_config():
    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f)

def load_seen(state_file):
    seen = {}
    if state_file.exists():
        for line in state_file.read_text().splitlines():
            if "|" in line:
                cid, mod = line.strip().split("|", 1)
                seen[cid] = mod
    return seen

def save_seen(seen, state_file):
    with state_file.open("w") as f:
        for cid, mod in seen.items():
            f.write(f"{cid}|{mod}\n")

# ---------------- Email ----------------
def send_email(subject, html_body, recipients, config):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config["email"]["email_from"]

        if isinstance(recipients, str):
            recipients = [recipients]
        msg["To"] = ", ".join(recipients)

        part1 = MIMEText("Please view this email in an HTML-capable client.", "plain")
        part2 = MIMEText(html_body, "html")
        msg.attach(part1)
        msg.attach(part2)

        smtp_server = config["email"]["smtp_server"]
        smtp_port = config["email"]["smtp_port"]
        auth_type = str(config["email"].get("auth_type", "none")).lower()

        if auth_type == "ssl":
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            if auth_type == "tls":
                try:
                    server.starttls()
                except Exception as e:
                    logging.warning(f"STARTTLS failed: {e}")

        user = config["email"].get("smtp_user")
        passwd = config["email"].get("smtp_pass")
        if auth_type in ("tls", "ssl") and user and passwd:
            server.login(user, passwd)

        server.sendmail(config["email"]["email_from"], recipients, msg.as_string())
        server.quit()
        logging.info(f"Sent email to {recipients}: {subject}")
    except Exception as e:
        msg = f"Error sending email: {e}"
        logging.error(msg, exc_info=True)
        log_warnings.append(msg)


def send_error_report(config):
    if not log_warnings:
        return

    today = datetime.now().strftime("%Y-%m-%d")
    if ERROR_STATE_FILE.exists():
        last_sent = ERROR_STATE_FILE.read_text().strip()
        if last_sent == today:
            logging.info("Error report already sent today, skipping duplicate.")
            return

    recipients = config["email"]["realtime_recipients"]
    subject = f"⚠️ CVE Alert Script Errors ({datetime.now().strftime('%Y-%m-%d %H:%M')})"

    warnings_html = "".join(f"<li>{w}</li>" for w in log_warnings)
    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;line-height:1.5;">
    <h2>⚠️ CVE Alert Script Errors</h2>
    <ul>{warnings_html}</ul>
    <h3>📊 Run Summary</h3>
    <ul>
      <li>CVEs Found: {metrics['cves_found']}</li>
      <li>CVEs Sent: {metrics['cves_sent']}</li>
      <li>CVEs Skipped: {metrics['cves_skipped']}</li>
    </ul>
    <p>Further errors today will only be logged, not emailed.</p>
    </body></html>
    """

    send_email(subject, html_body, recipients, config)
    ERROR_STATE_FILE.write_text(today)

# --------- Dump cpes for testing ------------
def dump_cpes(config, days=1):
    data = fetch_recent_cves(days)
    if not data:
        return

    unique_cpes = set()

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]

        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_uri = match.get("criteria", "").lower()
                    parts = cpe_uri.split(":")
                    if len(parts) < 6:
                        continue

                    cpe_vendor = parts[3]
                    cpe_product = parts[4]
                    cpe_version = parts[5]
                    unique_cpes.add((cpe_vendor, cpe_product, cpe_version))

    print("\n📋 Unique Vendor:Product:Version tuples in last", days, "days:\n")
    for vendor, product, version in sorted(unique_cpes):
        print(f"{vendor:15} {product:25} {version}")
    
    # Export to CSV file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = os.path.join(script_dir, f"cpe_export_{days}days_{timestamp}.csv")
    
    try:
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write("vendor,product,version\n")
            for vendor, product, version in sorted(unique_cpes):
                # Escape commas in fields
                vendor_escaped = f'"{vendor}"' if "," in vendor else vendor
                product_escaped = f'"{product}"' if "," in product else product
                version_escaped = f'"{version}"' if "," in version else version
                f.write(f"{vendor_escaped},{product_escaped},{version_escaped}\n")
        
        print(f"\n✅ Exported {len(unique_cpes)} CPE entries to: {csv_file}")
    except Exception as e:
        print(f"⚠️  Failed to export CSV: {e}")

# --------- Validate filters against actual CPE data ------------
def validate_filters(config, days=90):
    """Validate configured filters against actual CPE data and suggest corrections."""
    print(f"\n🔍 Validating filters against {days} days of CVE data...")
    data = fetch_recent_cves(days)
    if not data:
        print("❌ Failed to fetch CVE data")
        return

    # Collect all unique vendor/product combinations
    actual_cpes = defaultdict(set)  # vendor -> set of products
    actual_versions = defaultdict(set)  # (vendor, product) -> set of versions
    
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_uri = match.get("criteria", "").lower()
                    parts = cpe_uri.split(":")
                    if len(parts) < 6:
                        continue
                    
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5]
                    
                    actual_cpes[vendor].add(product)
                    actual_versions[(vendor, product)].add(version)
    
    print(f"✅ Found {len(actual_cpes)} unique vendors in {days} days of data\n")
    
    # Validate configured filters
    configured_filters = config["filters"]["products"]
    suggestions = []
    issues = []
    
    for filter_item in configured_filters:
        vendor = filter_item["vendor"].lower()
        products = filter_item.get("product", "*")
        versions = filter_item.get("version", "*")
        
        # Normalize to lists
        if isinstance(products, str):
            products = [products]
        if isinstance(versions, str):
            versions = [versions]
        
        # Check if vendor exists
        if vendor not in actual_cpes:
            vendor_matches = get_close_matches(vendor, actual_cpes.keys(), n=3, cutoff=0.6)
            issues.append({
                "type": "vendor_not_found",
                "vendor": vendor,
                "suggestions": vendor_matches,
                "original": filter_item
            })
            print(f"⚠️  Vendor '{vendor}' not found in recent CVEs")
            if vendor_matches:
                print(f"   Did you mean: {', '.join(vendor_matches)}")
            print()
            continue
        
        # Check products
        available_products = list(actual_cpes[vendor])
        for product in products:
            if product == "*":
                continue
            
            # Handle wildcards
            product_base = product.rstrip("*")
            if product.endswith("*"):
                # Check if any actual products start with this base
                matches = [p for p in available_products if p.startswith(product_base)]
                if not matches:
                    fuzzy_matches = get_close_matches(product_base, available_products, n=3, cutoff=0.6)
                    issues.append({
                        "type": "product_not_found",
                        "vendor": vendor,
                        "product": product,
                        "suggestions": fuzzy_matches,
                        "original": filter_item
                    })
                    print(f"⚠️  Product pattern '{product}' (vendor: {vendor}) has no matches")
                    if fuzzy_matches:
                        print(f"   Similar products: {', '.join(fuzzy_matches)}")
                    print(f"   Available products for {vendor}: {', '.join(sorted(available_products)[:5])}...")
                    print()
            else:
                # Exact match
                if product not in available_products:
                    fuzzy_matches = get_close_matches(product, available_products, n=3, cutoff=0.6)
                    issues.append({
                        "type": "product_not_found",
                        "vendor": vendor,
                        "product": product,
                        "suggestions": fuzzy_matches,
                        "original": filter_item
                    })
                    print(f"⚠️  Product '{product}' not found for vendor '{vendor}'")
                    if fuzzy_matches:
                        print(f"   Did you mean: {', '.join(fuzzy_matches)}")
                    print(f"   Available products: {', '.join(sorted(available_products)[:10])}")
                    print()
    
    # Generate corrected config
    if issues:
        print("\n" + "="*70)
        print("📝 Generating corrected config based on suggestions...")
        print("="*70 + "\n")
        
        corrected_filters = []
        for filter_item in configured_filters:
            vendor = filter_item["vendor"].lower()
            
            # Find if this filter has issues
            filter_issues = [i for i in issues if i["original"] == filter_item]
            
            if not filter_issues:
                # No issues, keep as is
                corrected_filters.append(filter_item)
                continue
            
            # Check for vendor issues first
            vendor_issue = next((i for i in filter_issues if i["type"] == "vendor_not_found"), None)
            if vendor_issue and vendor_issue["suggestions"]:
                # Use best vendor match
                new_vendor = vendor_issue["suggestions"][0]
                new_filter = filter_item.copy()
                new_filter["vendor"] = new_vendor
                corrected_filters.append(new_filter)
                print(f"✏️  Changed vendor '{vendor}' → '{new_vendor}'")
                continue
            
            # Check for product issues
            product_issues = [i for i in filter_issues if i["type"] == "product_not_found"]
            if product_issues:
                new_filter = filter_item.copy()
                products = new_filter.get("product", "*")
                if isinstance(products, str):
                    products = [products]
                
                new_products = []
                for prod in products:
                    issue = next((i for i in product_issues if i["product"] == prod), None)
                    if issue and issue["suggestions"]:
                        new_prod = issue["suggestions"][0]
                        new_products.append(new_prod)
                        print(f"✏️  Changed product '{prod}' → '{new_prod}' (vendor: {vendor})")
                    else:
                        new_products.append(prod)
                
                if len(new_products) == 1:
                    new_filter["product"] = new_products[0]
                else:
                    new_filter["product"] = new_products
                corrected_filters.append(new_filter)
            else:
                corrected_filters.append(filter_item)
        
        # Write corrected config
        output_file = os.path.join(script_dir, "config.suggested.yaml")
        corrected_config = config.copy()
        corrected_config["filters"]["products"] = corrected_filters
        
        with open(output_file, "w") as f:
            yaml.dump(corrected_config, f, default_flow_style=False, sort_keys=False)
        
        print(f"\n✅ Corrected configuration written to: {output_file}")
        print(f"   Review the changes and rename to config.yaml if acceptable")
    else:
        print("✅ All filters look good! No issues found.")
    
    print(f"\n💡 Tip: Run with --dump-cpes --days {days} to see all available vendor:product combinations")

# ---------------- CVE Handling ----------------
def fetch_recent_cves(days=1):
    try:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        start = now - timedelta(days=days)

        all_cves = {"vulnerabilities": []}

        # NVD safe window — don't query bigger than ~90 days per request
        step = timedelta(days=90)
        chunk_start = start

        while chunk_start < now:
            chunk_end = min(chunk_start + step, now)
            logging.debug(f"Fetching CVEs from {chunk_start} to {chunk_end}")

            start_index = 0
            page_size = 2000  # NVD max

            while True:
                params = {
                    "pubStartDate": chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "pubEndDate": chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                }

                response = requests.get(NVD_API, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()

                vulns = data.get("vulnerabilities", [])
                logging.debug(f"Chunk {chunk_start}–{chunk_end}, got {len(vulns)} results (index {start_index}).")

                all_cves["vulnerabilities"].extend(vulns)

                # stop paging if fewer than page_size
                if len(vulns) < page_size:
                    break

                start_index += page_size

            # move to next time chunk
            chunk_start = chunk_end

        logging.info(f"Fetched total {len(all_cves['vulnerabilities'])} CVEs over {days} days.")
        return all_cves

    except Exception as e:
        msg = f"Error fetching CVEs from NVD: {e}"
        logging.error(msg, exc_info=True)
        log_warnings.append(msg)
        return {"vulnerabilities": []}

def cve_matches_products(cve, products):
    try:
        # Priority 1: Check CPE Configurations (Exact Match)
        configs = cve.get("configurations", [])
        for conf in configs:
            nodes = conf.get("nodes", [])
            conf_operator = conf.get("operator", "OR")
            
            # If this is an AND configuration with multiple nodes, it likely means
            # "App X running on Platform Y". We only want to match the primary (first) node,
            # not the platform nodes. This prevents Chrome-on-Windows from matching Windows filters.
            is_platform_config = conf_operator == "AND" and len(nodes) > 1
            
            for node_index, node in enumerate(nodes):
                # In AND configs, skip non-primary nodes (platforms like Windows, Linux)
                # Primary node is usually index 0 (the actual vulnerable software)
                if is_platform_config and node_index > 0:
                    logging.debug(f"Skipping platform node {node_index} in AND configuration for {cve.get('id')}")
                    continue
                    
                for match in node.get("cpeMatch", []):
                    cpe_uri = match.get("criteria", "").lower()
                    parts = cpe_uri.split(":")
                    if len(parts) < 6:
                        continue

                    cpe_vendor = parts[3]      # e.g. sonicwall
                    cpe_product = parts[4]     # e.g. sonicos
                    cpe_version = parts[5]     # e.g. *, -, specific version string

                    for p in products:
                        vendor = p["vendor"].lower()
                        prods = p["product"]
                        vers = p.get("version", "*")

                        # Normalize to lists and lowercase
                        if isinstance(prods, str):
                            prods = [prods]
                        prods = [x.lower() for x in prods]

                        if isinstance(vers, str):
                            vers = [vers]
                        vers = [x.lower() for x in vers]

                        if cpe_vendor == vendor:
                            for prod in prods:
                                if prod == "*" or (prod.endswith("*") and cpe_product.startswith(prod[:-1])) or (cpe_product == prod):
                                    for v in vers:
                                        if v == "*" or (v.endswith("*") and cpe_version.startswith(v[:-1])) or (cpe_version == v) or (cpe_version in ["-", ""] and v == "*"):
                                            logging.debug(f"CPE match: {cve.get('id')} matched filter vendor={vendor} product={prod} via CPE {cpe_uri}")
                                            return vendor

        # Priority 2: Fallback to Description Search (Fuzzy Match)
        # Only applies to filters with fuzzy_match: true
        # Requires BOTH vendor AND product to be present in description (strict mode)
        descriptions = cve.get("descriptions", [])
        if not descriptions:
            return None
            
        desc_text = descriptions[0].get("value", "").lower()
        
        for p in products:
            # Skip fuzzy matching if not enabled for this filter
            if not p.get("fuzzy_match", False):
                continue
                
            vendor = p["vendor"].lower()
            prods = p["product"]
            
            if isinstance(prods, str):
                prods = [prods]
            prods = [x.lower() for x in prods]
            
            # Check if vendor is in description (as whole word)
            vendor_pattern = r'\b' + re.escape(vendor) + r'\b'
            vendor_found = bool(re.search(vendor_pattern, desc_text, re.IGNORECASE))
            
            # Strict mode: vendor MUST be found for fuzzy matching
            if not vendor_found:
                continue
            
            for prod in prods:
                # If product is "*", checking vendor is enough
                if prod == "*":
                    logging.debug(f"Found fuzzy match (Vendor only) in description for {vendor}")
                    return vendor
                    
                # Strip wildcard for text search
                clean_prod = prod.replace("_", " ").rstrip("*")
                
                # Skip very short product names for safety
                if len(clean_prod) < 3:
                    continue
                
                # Use word boundary matching to avoid "office" matching "Woffice"
                # Try both underscore version and space version
                prod_pattern = r'\b' + re.escape(clean_prod) + r'\b'
                prod_pattern_underscore = r'\b' + re.escape(prod.rstrip("*")) + r'\b'
                prod_found = bool(re.search(prod_pattern, desc_text, re.IGNORECASE)) or \
                             bool(re.search(prod_pattern_underscore, desc_text, re.IGNORECASE))
                
                # Strict mode: require BOTH vendor AND product
                if prod_found:
                    logging.debug(f"Found fuzzy match (Vendor+Product) in description for {vendor} {prod}")
                    return vendor

    except Exception as e:
        msg = f"Error parsing CVE {cve.get('id','unknown')}: {e}"
        logging.error(msg, exc_info=True)
        log_warnings.append(msg)
    return None

def severity_badge(cvss):
    if cvss is None:
        return '<span class="badge na">N/A</span>'
    score = float(cvss)
    if score >= 9.0:
        return f'<span class="badge critical">Critical {score}</span>'
    elif score >= 7.0:
        return f'<span class="badge high">High {score}</span>'
    elif score >= 4.0:
        return f'<span class="badge medium">Medium {score}</span>'
    elif score > 0.0:
        return f'<span class="badge low">Low {score}</span>'
    return '<span class="badge na">N/A</span>'


def parse_and_alert(config, days=1, digest_mode=False):
    # Use separate state files for digest vs realtime
    mode_name = "DIGEST" if digest_mode else "REALTIME"
    state_file = STATE_FILE_DIGEST if digest_mode else STATE_FILE_REALTIME
    logging.debug(f"[{mode_name}] Starting parse_and_alert for {days} day(s)")
    logging.debug(f"[{mode_name}] Using state file: {state_file}")
    
    seen = load_seen(state_file)
    logging.debug(f"[{mode_name}] Loaded {len(seen)} previously seen CVEs from state file")
    
    data = fetch_recent_cves(days)
    if not data:
        logging.warning(f"[{mode_name}] No CVE data returned from API, exiting")
        return

    new_entries = defaultdict(list)
    updated_entries = defaultdict(list)
    realtime_alerts = []  # For realtime mode

    metrics["cves_found"] = 0
    metrics["cves_sent"] = 0
    metrics["cves_skipped"] = 0
    
    matched_count = 0
    no_match_count = 0
    cvss_skip_count = 0
    already_seen_count = 0

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        published = cve["published"]
        modified = cve["lastModified"]

        desc_list = cve.get("descriptions", [])
        description = desc_list[0]["value"] if desc_list else "No description"

        cvss_score = None
        metricsBlock = cve.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metricsBlock:
                cvss_score = metricsBlock[key][0]["cvssData"]["baseScore"]
                break

        metrics["cves_found"] += 1

        vendor = cve_matches_products(cve, config["filters"]["products"])
        if not vendor:
            no_match_count += 1
            continue

        min_cvss = config["filters"].get("min_cvss", 0)
        if cvss_score is None or cvss_score < min_cvss:
            logging.debug(f"[{mode_name}] {cve_id} matched {vendor} but CVSS {cvss_score} < min_cvss {min_cvss}, skipping")
            metrics["cves_skipped"] += 1
            cvss_skip_count += 1
            continue

        # Determine status (new vs updated)
        if cve_id not in seen:
            status = "new"
            seen[cve_id] = modified
            logging.debug(f"[{mode_name}] {cve_id} is NEW (vendor={vendor}, CVSS={cvss_score})")
        else:
            if modified > seen[cve_id]:
                status = "updated"
                seen[cve_id] = modified
                logging.debug(f"[{mode_name}] {cve_id} is UPDATED (vendor={vendor}, CVSS={cvss_score})")
            else:
                already_seen_count += 1
                continue
        
        matched_count += 1

        references = [ref.get("url", "") for ref in cve.get("references", []) if "url" in ref]
        
        # Store CVE data for later deduplication
        cve_data = {
            "cve_id": cve_id,
            "vendor": vendor.title(),
            "cvss_score": cvss_score,
            "description": description,
            "references": references,
            "published": published,
            "modified": modified,
            "status": status
        }

        if digest_mode:
            if status == "new":
                new_entries[vendor.title()].append(cve_data)
            else:
                updated_entries[vendor.title()].append(cve_data)
        else:
            realtime_alerts.append(cve_data)

    save_seen(seen, state_file)
    
    # Deduplicate CVEs with identical titles (first sentence of description)
    def extract_title(description):
        """Extract the title (first sentence) from a CVE description."""
        # Split on common sentence endings
        for sep in ['. ', '.\n', '.\t']:
            if sep in description:
                return description.split(sep)[0].strip()
        return description.strip()
    
    def deduplicate_cves(cve_list):
        """Group CVEs with identical titles and merge them."""
        if not cve_list:
            return []
        
        # Group by title (first sentence)
        title_groups = defaultdict(list)
        for cve_data in cve_list:
            title = extract_title(cve_data["description"])
            title_groups[title].append(cve_data)
        
        # Merge groups
        deduplicated = []
        for title, group in title_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Merge multiple CVEs with same description
                merged = group[0].copy()
                all_cve_ids = [c["cve_id"] for c in group]
                all_refs = []
                for c in group:
                    all_refs.extend(c["references"])
                all_refs = list(set(all_refs))  # Deduplicate references
                
                # Use highest CVSS score
                max_cvss = max(c["cvss_score"] for c in group if c["cvss_score"] is not None)
                
                merged["cve_id"] = ", ".join(all_cve_ids)
                merged["cve_count"] = len(group)
                merged["cvss_score"] = max_cvss
                merged["references"] = all_refs
                
                logging.debug(f"[{mode_name}] Merged {len(group)} CVEs with identical description: {all_cve_ids}")
                deduplicated.append(merged)
        
        return deduplicated
    
    # Apply deduplication to digest entries
    for vendor_name in new_entries:
        original_count = len(new_entries[vendor_name])
        new_entries[vendor_name] = deduplicate_cves(new_entries[vendor_name])
        if len(new_entries[vendor_name]) < original_count:
            logging.info(f"[{mode_name}] Deduplicated {vendor_name} new entries: {original_count} → {len(new_entries[vendor_name])}")
    
    for vendor_name in updated_entries:
        original_count = len(updated_entries[vendor_name])
        updated_entries[vendor_name] = deduplicate_cves(updated_entries[vendor_name])
        if len(updated_entries[vendor_name]) < original_count:
            logging.info(f"[{mode_name}] Deduplicated {vendor_name} updated entries: {original_count} → {len(updated_entries[vendor_name])}")
    
    # Helper to generate HTML for a CVE entry
    def generate_entry_html(cve_data):
        badge = severity_badge(cve_data["cvss_score"])
        refs_html = "".join(f'<li><a href="{ref}">{ref}</a></li>' for ref in cve_data["references"])
        
        # Generate CVE links - handle both single and merged CVEs
        cve_ids = cve_data["cve_id"].split(", ")
        cve_links = ", ".join(
            f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" style="color:#1a237e;">{cve_id}</a>'
            for cve_id in cve_ids
        )
        
        cve_count = cve_data.get("cve_count", 1)
        if cve_count > 1:
            header = f"{cve_links} {badge} <span style='color:#666;'>({cve_count} related CVEs)</span>"
        else:
            header = f"{cve_links} {badge}"
        
        return f"""
        <div class="cve-entry {'updated' if cve_data['status']=='updated' else ''}">
          <div class="cve-header">{header}</div>
          <p><b>Vendor:</b> {cve_data['vendor']}<br>
             <b>Published:</b> {cve_data['published']}<br>
             <b>Last Modified:</b> {cve_data['modified']}</p>
          <p>{cve_data['description']}</p>
          <b>References:</b>
          <ul>{refs_html}</ul>
        </div>
        """
    
    # Log summary of processing
    total_new = sum(len(v) for v in new_entries.values())
    total_updated = sum(len(v) for v in updated_entries.values())
    logging.info(f"[{mode_name}] Processing complete: {metrics['cves_found']} CVEs fetched, {matched_count} matched filters, {cvss_skip_count} skipped (CVSS), {already_seen_count} already seen, {no_match_count} no match")
    logging.info(f"[{mode_name}] After deduplication: {total_new} new, {total_updated} updated entries")

    # Digest mode: send one batched email
    if digest_mode and (new_entries or updated_entries):
        today = datetime.now().strftime("%Y-%m-%d")
        total = sum(len(v) for v in new_entries.values()) + sum(len(v) for v in updated_entries.values())
        subject_template = config["email"].get(
            "subject_template", "[CVE Digest] {count} New/Updated CVEs ({date})"
        )
        subject = subject_template.format(count=total, date=today)

        sections = ""
        if new_entries:
            sections += "<h2>New CVEs</h2>"
            for vendor, entries in new_entries.items():
                sections += f"<h3>{vendor}</h3>"
                for cve_data in entries:
                    sections += generate_entry_html(cve_data)

        if updated_entries:
            sections += "<h2>Updated CVEs</h2>"
            for vendor, entries in updated_entries.items():
                sections += f"<h3>{vendor}</h3>"
                for cve_data in entries:
                    sections += generate_entry_html(cve_data)

        html_body = f"""
        <html>
        <head>
          <style>
            body {{ font-family: Arial, sans-serif; line-height:1.5; color:#333; }}
            h1 {{ color:#2e3b4e; }}
            h2 {{ margin-top:30px; border-bottom:2px solid #eee; padding-bottom:5px; }}
            .cve-entry {{ border:1px solid #ddd; margin:10px 0; padding:10px;
                          border-radius:6px; background:#fafafa; }}
            .cve-entry.updated {{ border-left:4px solid #2196f3; background:#f5faff; }}
            .cve-header {{ font-weight:bold; font-size:14px; color:#1a237e; margin-bottom:5px; }}
            .badge {{ padding:2px 6px; border-radius:4px; font-weight:bold; font-size:12px; }}
            .critical {{ background:#d32f2f; color:white; }}
            .high {{ background:#f57c00; color:white; }}
            .medium {{ background:#fbc02d; color:black; }}
            .low {{ background:#388e3c; color:white; }}
            .na {{ background:#9e9e9e; color:white; }}
            ul {{ margin:5px 0 5px 15px; }}
          </style>
        </head>
        <body>
          <h1>CVE Digest</h1>
          <p>Showing CVEs from the past {days} day(s).</p>
          {sections}
        </body>
        </html>
        """

        logging.debug(f"[{mode_name}] Preparing to send digest email with {total} CVEs to {config['email']['digest_recipients']}")
        send_email(subject, html_body, config["email"]["digest_recipients"], config)
        logging.info(f"[{mode_name}] Digest sent with {total} items ({sum(len(v) for v in new_entries.values())} new, {sum(len(v) for v in updated_entries.values())} updated)")
    elif digest_mode:
        logging.info(f"[{mode_name}] No new/updated CVEs to send - no digest email generated")

    # Realtime mode: send individual emails per CVE
    if not digest_mode and realtime_alerts:
        for alert in realtime_alerts:
            status_label = "🆕 NEW" if alert["status"] == "new" else "🔄 UPDATED"
            subject = f"[CVE Alert] {status_label} {alert['cve_id']} ({alert['vendor']}) - CVSS {alert['cvss_score']}"
            
            html_body = f"""
            <html>
            <head>
              <style>
                body {{ font-family: Arial, sans-serif; line-height:1.5; color:#333; }}
                .cve-entry {{ border:1px solid #ddd; margin:10px 0; padding:15px;
                              border-radius:6px; background:#fafafa; }}
                .cve-entry.updated {{ border-left:4px solid #2196f3; background:#f5faff; }}
                .cve-header {{ font-weight:bold; font-size:16px; color:#1a237e; margin-bottom:10px; }}
                .badge {{ padding:2px 6px; border-radius:4px; font-weight:bold; font-size:12px; }}
                .critical {{ background:#d32f2f; color:white; }}
                .high {{ background:#f57c00; color:white; }}
                .medium {{ background:#fbc02d; color:black; }}
                .low {{ background:#388e3c; color:white; }}
                .na {{ background:#9e9e9e; color:white; }}
                ul {{ margin:5px 0 5px 15px; }}
              </style>
            </head>
            <body>
              <h1>⚠️ CVE Alert: {alert['cve_id']}</h1>
              {alert['entry_html']}
            </body>
            </html>
            """
            
            logging.debug(f"[{mode_name}] Sending realtime alert for {alert['cve_id']} to {config['email']['realtime_recipients']}")
            send_email(subject, html_body, config["email"]["realtime_recipients"], config)
            metrics["cves_sent"] += 1
        
        logging.info(f"[{mode_name}] Sent {len(realtime_alerts)} individual CVE alerts to {config['email']['realtime_recipients']}")
    elif not digest_mode:
        logging.info(f"[{mode_name}] No new/updated CVEs to send - no realtime alerts generated")

# ---------------- Main ----------------
def main():
    global log_warnings
    parser = argparse.ArgumentParser(description="CVE Alert Script")
    parser.add_argument("--digest", action="store_true", help="Run in digest mode (daily summary)")
    parser.add_argument("--realtime", action="store_true", help="Run in realtime alert mode (per CVE)")
    parser.add_argument("--dump-cpes", action="store_true", help="Dump vendor:product:version combinations")
    parser.add_argument("--validate-filters", action="store_true", help="Validate configured filters against actual CPE data")
    parser.add_argument("--days", type=int, default=1, help="How many past days of CVEs to query (default=1)")
    args = parser.parse_args()

    config = load_config()
    setup_logging(config)

    try:
        if args.validate_filters:
            validate_filters(config, days=args.days if args.days > 1 else 90)
        elif args.dump_cpes:
            dump_cpes(config, days=args.days)
        elif args.digest:
            parse_and_alert(config, days=args.days, digest_mode=True)
        elif args.realtime:
            parse_and_alert(config, days=args.days, digest_mode=False)
        else:
            logging.warning("No mode selected. Use --digest, --realtime, --dump-cpes, or --validate-filters.")
    except Exception as e:
        msg = f"Fatal error in main(): {e}"
        logging.critical(msg, exc_info=True)
        log_warnings.append(msg)
    finally:
        try:
            if log_warnings:
                send_error_report(config)
        except Exception as e:
            logging.error(f"Failed sending error report: {e}", exc_info=True)

if __name__ == "__main__":
    main()