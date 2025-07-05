# OSINT Forge

**OSINT Forge** is a professional-grade, API-free OSINT toolkit designed for government and cybersecurity professionals. It provides advanced scanning capabilities without requiring API keys or tokens.

## ✨ Features

- **Username OSINT**: Scan usernames across 100+ popular sites.
- **Email OSINT**: Analyze emails, perform Gravatar lookups, and check for breaches.
- **Domain OSINT**: Perform WHOIS lookups, DNS analysis, and certificate transparency monitoring.
- **Phone OSINT**: Analyze phone numbers and check for breaches.
- **IP OSINT**: Geolocate IPs and analyze their reputation.
- **Subdomain Scanning**: Enumerate subdomains and detect takeover vulnerabilities.
- **API Endpoint Discovery**: Discover hidden API endpoints using wordlists.
- **Content Discovery**: Brute-force directories and files on web servers.
- **Metadata Extraction**: Extract metadata and Exif data from images and documents.
- **IoT Scanning**: Scan for exposed IoT devices and network services.
- **Darknet Scanning**: Search darknet marketplaces and forums for keywords.
- **Custom Commands**: Run arbitrary commands with the `custom` subparser.

## 🛠️ Support

If you need help or encounter any issues, feel free to reach out:
- **Discord**: [@bearertoken](https://discord.com)
- **Email**: inukedyouyt@gmail.com

## 🚀 Quick Start

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/trob/osint-forge.git
   cd osint-forge
   ```

2. **Install Python 3.7+** if not already installed.

3. **Install Dependencies**:
   ```bash
   python -m pip install -r requirements.txt
   ```

4. **Run the Tool**:
   ```bash
   python main.py
   ```

### Usage

Run the tool using the following syntax:
```bash
python main.py [subcommand] [options]
```

#### Subcommands and Examples

- **Username OSINT (`user`)**:
  ```bash
  python main.py user johndoe --threads 20 --timeout 10 --site-limit 50 --fast
  ```
  - `--threads`: Number of threads (default: 10).
  - `--timeout`: Timeout per request in seconds (default: 5).
  - `--site-limit`: Limit the number of sites to check (default: all).
  - `--fast`: Scan only the first 100 sites for speed.

- **Email OSINT (`email`)**:
  ```bash
  python main.py email johndoe@example.com
  ```

- **IP OSINT (`ip`)**:
  ```bash
  python main.py ip 192.168.1.1
  ```

- **Phone OSINT (`phone`)**:
  ```bash
  python main.py phone +1234567890
  ```

- **Domain OSINT (`domain`)**:
  ```bash
  python main.py domain example.com --spider
  ```
  - `--spider`: Spider crawl the domain after OSINT.

- **Reverse Image Search (`reverseimg`)**:
  ```bash
  python main.py reverseimg /path/to/image.jpg
  ```

- **Email Pattern Generator (`emailpattern`)**:
  ```bash
  python main.py emailpattern "John Doe" example.com
  ```

- **Metadata Extraction (`metadata`)**:
  ```bash
  python main.py metadata /path/to/file
  ```

- **Custom Scan (`customscan`)**:
  ```bash
  python main.py customscan johndoe --sites github twitter --threads 15 --timeout 10
  ```
  - `--sites`: List of sites to scan (site keys from `site_list.py`).
  - `--threads`: Number of threads (default: 10).
  - `--timeout`: Timeout per request in seconds (default: 5).

- **Discord OSINT (`discord`)**:
  ```bash
  python main.py discord johndoe#1234 --avatar --servers
  ```
  - `--avatar`: Get Discord avatar URL.
  - `--servers`: Search Discord servers.

### Custom Commands

The `custom` subparser allows you to run arbitrary commands. For example:
```bash
python main.py customscan johndoe --sites github twitter
```
This scans the specified sites for the given username.

## 📄 License

This project is licensed under the MIT License.
