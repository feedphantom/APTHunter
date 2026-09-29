# 🕵️ APTHunter

APTHunter is a Python command-line and Streamlit application for exploring threat groups and related data from the public [MITRE ATT&CK Enterprise dataset](https://attack.mitre.org/).

The web app lets you search groups by country, alias, or sector; inspect tactics, techniques, malware, tools, and campaigns; and view summary statistics. The CLI supports the same group filters and can export matching groups to CSV.

## Features

- Search ATT&CK groups by country, alias, or targeted sector.
- Review group aliases, descriptions, tactics, techniques, sectors, and MITRE references.
- Browse ATT&CK tactics and techniques, including technique mitigations.
- Explore documented malware, tools, and campaigns.
- View statistics for countries, techniques, malware, and sectors.
- Export filtered group results to CSV from the CLI.

## Requirements

- Python and pip
- Dependencies listed in `requirements.txt`

## Setup

Run these commands from the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Run the web app

```bash
streamlit run app.py
```

The app reads the ATT&CK data from `data/enterprise-attack.json`. It displays the dataset version when available and can notify you when MITRE publishes a newer ATT&CK spec version.

## Run the CLI

Start the interactive menu:

```bash
python apt_hunter.py
```

Or pass a filter directly:

```bash
python apt_hunter.py --country Russia
python apt_hunter.py --alias APT29
python apt_hunter.py --sector energy
```

Filters can be combined. For example, search for groups matching both country and sector:

```bash
python apt_hunter.py --country Russia --sector government
```

Export the matching groups to CSV:

```bash
python apt_hunter.py --country Russia --export-csv russia-groups.csv
```

Use `python apt_hunter.py --help` to see the available options.

## Data and interpretation

APTHunter uses MITRE ATT&CK Enterprise data. Country and sector filters use the corresponding fields in each group record; they do not infer targeting from a group's description. Coverage varies by group, so missing country or sector values mean the dataset does not provide that field.

Relationships and attributions shown by the app reflect the source dataset. They are not independent confirmation that an operation or group attribution is correct. Check the linked MITRE ATT&CK pages and other primary sources before relying on the information.

## Project structure

```text
app.py                  Streamlit web application
apt_hunter.py           Command-line interface
apt_hunter/
  core.py               ATT&CK data loading and group normalization
  filters.py            Group filters
  output.py             CLI output formatting
data/
  choices.json          Common search choices
  enterprise-attack.json ATT&CK Enterprise dataset snapshot
requirements.txt        Python dependencies
```

## Contributing

Bug reports and pull requests are welcome. For changes to filters or data handling, include a small reproducible example or test case where possible.

## Credits

- [MITRE ATT&CK](https://attack.mitre.org/) and the [MITRE ATT&CK Python Client](https://github.com/OTRF/ATTACK-Python-Client)
- [Streamlit](https://streamlit.io/)

## License

APTHunter is distributed under the MIT License. See [LICENSE](LICENSE).
