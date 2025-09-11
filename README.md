# CVE Grabber

A Python script to monitor and alert on new and updated Common Vulnerabilities and Exposures (CVEs) from the National Vulnerability Database (NVD). It fetches recent CVEs, filters them based on configured products/vendors, and sends HTML email alerts in digest or realtime mode.

## Features

- **CVE Monitoring**: Fetches recent CVEs from the NVD API with support for querying multiple days
- **Flexible Filtering**: Filter CVEs by vendor, product, and version with wildcard support
- **Email Alerts**: Send HTML-formatted email alerts with severity badges and detailed information
- **Digest Mode**: Daily summary emails grouping new and updated CVEs by vendor
- **Realtime Mode**: Immediate alerts for individual CVEs (per CVE basis)
- **State Tracking**: Tracks seen CVEs to avoid duplicate notifications
- **Comprehensive Logging**: Configurable logging with file rotation (daily or size-based)
- **Error Reporting**: Automatic error reporting via email with run metrics
- **CPE Dumping**: Utility to dump unique vendor:product:version combinations for testing

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/derrynj/cveGrabber.git
   cd cveGrabber
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Copy the example configuration:
   ```bash
   cp config.example.yaml config.yaml
   ```

4. Edit `config.yaml` with your settings (see Configuration section below)

## Configuration

The script uses a YAML configuration file (`config.yaml`). Copy from `config.example.yaml` and customize it with your settings.

### Configuration Sections

- **Email Settings**: Configure SMTP server, authentication, recipients, and email templates
- **Logging Configuration**: Set log file location, level, and rotation policies
- **CVE Filters**: Define which vendors/products to monitor and minimum CVSS score thresholds

See `config.example.yaml` for detailed configuration options and examples.

## Usage

### Basic Commands

Run in digest mode (daily summary):
```bash
python cveGrabber.py --digest
```

Run in realtime mode (immediate alerts):
```bash
python cveGrabber.py --realtime
```

Dump CPE combinations for testing:
```bash
python cveGrabber.py --dump-cpes
```

### Command Line Options

- `--digest`: Run in digest mode (daily summary email)
- `--realtime`: Run in realtime alert mode (per CVE)
- `--dump-cpes`: Dump vendor:product:version combinations
- `--days`: Number of past days to query (default: 1)

### Examples

Check for CVEs from the last 7 days in digest mode:
```bash
python cveGrabber.py --digest --days 7
```

Get realtime alerts for yesterday's CVEs:
```bash
python cveGrabber.py --realtime --days 1
```

Dump CPE data for analysis:
```bash
python cveGrabber.py --dump-cpes --days 30
```

## Email Format

The script sends HTML-formatted emails with:

- **Severity Badges**: Color-coded CVSS scores (Critical, High, Medium, Low, N/A)
- **CVE Details**: ID, vendor, publication date, last modified date
- **Description**: Full CVE description
- **References**: Links to additional information
- **Grouping**: In digest mode, CVEs are grouped by vendor with separate sections for new vs updated

## State Files

The script maintains state to avoid duplicate notifications:

- `seen_cves_cpe.txt`: Tracks seen CVEs with their last modified date
- `error_report_state.txt`: Tracks when error reports were last sent

## Dependencies

- `requests`: For API calls to NVD
- `PyYAML`: For configuration file parsing

## Requirements

- Python 3.6+
- Access to NVD API (no API key required)
- SMTP server for email delivery

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the GNU General Public License v3.0 - see the COPYING file for details.

## Disclaimer

This tool is provided as-is for monitoring CVEs. Always verify CVE information from official sources and assess the impact on your environment before taking action.

The majority of this repo was built with Generative AI models. Code has been checked for functionality, not sensibility or efficiency.