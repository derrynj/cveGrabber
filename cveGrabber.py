import requests
import smtplib
import yaml
import argparse
import logging
import os
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from difflib import get_close_matches
script_dir = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(script_dir, "config.yaml")
STATE_FILE = Path(os.path.join(script_dir, "seen_cves_cpe.txt"))
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

def load_seen():
    seen = {}
    if STATE_FILE.exists():
        for line in STATE_FILE.read_text().splitlines():
            if "|" in line:
                cid, mod = line.strip().split("|", 1)
                seen[cid] = mod
    return seen

def save_seen(seen):
    with STATE_FILE.open("w") as f:
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
            for node in conf.get("nodes", []):
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
                                            return vendor

        # Priority 2: Fallback to Description Search (Fuzzy Match)
        # Useful for new CVEs where NVD hasn't added CPEs yet
        descriptions = cve.get("descriptions", [])
        if not descriptions:
            return None
            
        desc_text = descriptions[0].get("value", "").lower()
        
        for p in products:
            vendor = p["vendor"].lower()
            prods = p["product"]
            
            if isinstance(prods, str):
                prods = [prods]
            prods = [x.lower() for x in prods]
            
            # Check if vendor is in description
            vendor_found = vendor in desc_text
            
            for prod in prods:
                # If product is "*", checking vendor is enough
                if prod == "*":
                    if vendor_found:
                        return vendor
                    continue
                    
                # Strip wildcard for text search
                clean_prod = prod.replace("_", " ").rstrip("*")
                
                # Skip very short product names for safety if vendor matches
                if len(clean_prod) < 3:
                    continue
                    
                # Check if product is in description
                prod_found = clean_prod in desc_text or prod.rstrip("*") in desc_text
                
                if vendor_found and prod_found:
                    logging.debug(f"Found fuzzy match (Vendor+Product) in description for {vendor} {prod}")
                    return vendor
                
                # Relaxed check: If product is distinctive (>= 6 chars), match even if vendor is missing
                # e.g. "SonicOS" implies SonicWall, "Android" implies Google/Samsung
                if not vendor_found and prod_found and len(clean_prod) >= 5:
                    logging.debug(f"Found fuzzy match (Product only) in description for {vendor} {prod}")
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
    seen = load_seen()
    data = fetch_recent_cves(days)
    if not data:
        return

    new_entries = defaultdict(list)
    updated_entries = defaultdict(list)

    metrics["cves_found"] = 0
    metrics["cves_sent"] = 0
    metrics["cves_skipped"] = 0

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
            continue

        min_cvss = config["filters"].get("min_cvss", 0)
        if cvss_score is None or cvss_score < min_cvss:
            metrics["cves_skipped"] += 1
            continue

        # Determine status (new vs updated)
        if cve_id not in seen:
            status = "new"
            seen[cve_id] = modified
        else:
            if modified > seen[cve_id]:
                status = "updated"
                seen[cve_id] = modified
            else:
                continue

        badge = severity_badge(cvss_score)
        references = "".join(
            f'<li><a href="{ref.get("url","")}">{ref.get("url","")}</a></li>'
            for ref in cve.get("references", []) if "url" in ref
        )
        entry_html = f"""
        <div class="cve-entry {'updated' if status=='updated' else ''}">
          <div class="cve-header">{cve_id} {badge}</div>
          <p><b>Vendor:</b> {vendor.title()}<br>
             <b>Published:</b> {published}<br>
             <b>Last Modified:</b> {modified}</p>
          <p>{description}</p>
          <b>References:</b>
          <ul>{references}</ul>
        </div>
        """

        if status == "new":
            new_entries[vendor.title()].append(entry_html)
        else:
            updated_entries[vendor.title()].append(entry_html)

    save_seen(seen)

    # Only digest mode groups/HTML sends
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
                for html in entries:
                    sections += html

        if updated_entries:
            sections += "<h2>Updated CVEs</h2>"
            for vendor, entries in updated_entries.items():
                sections += f"<h3>{vendor}</h3>"
                for html in entries:
                    sections += html

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

        send_email(subject, html_body, config["email"]["digest_recipients"], config)
        logging.info(f"Digest sent with {total} items ({sum(len(v) for v in new_entries.values())} new, {sum(len(v) for v in updated_entries.values())} updated)")

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