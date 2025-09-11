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

CONFIG_FILE = "config.yaml"
STATE_FILE = Path("seen_cves_cpe.txt")
ERROR_STATE_FILE = Path("error_report_state.txt")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

log_warnings = []  # track runtime/logging warnings
metrics = {"cves_found": 0, "cves_sent": 0, "cves_skipped": 0}


# ---------------- Logging Setup ----------------
def setup_logging(config):
    log_cfg = config.get("logging", {})
    log_file = log_cfg.get("log_file", "cve_alert.log")
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
                for _, html in sorted(entries, key=lambda x: x[0], reverse=True):
                    sections += html

        if updated_entries:
            sections += "<h2>Updated CVEs</h2>"
            for vendor, entries in updated_entries.items():
                sections += f"<h3>{vendor}</h3>"
                for _, html in sorted(entries, key=lambda x: x[0], reverse=True):
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
          <h1>Daily CVE Digest</h1>
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
    parser.add_argument("--days", type=int, default=1, help="How many past days of CVEs to query (default=1)")
    args = parser.parse_args()

    config = load_config()
    setup_logging(config)

    try:
        if args.dump_cpes:
            dump_cpes(config, days=args.days)
        elif args.digest:
            parse_and_alert(config, days=args.days, digest_mode=True)
        elif args.realtime:
            parse_and_alert(config, days=args.days, digest_mode=False)
        else:
            logging.warning("No mode selected. Use --digest, --realtime, or --dump-cpes.")
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