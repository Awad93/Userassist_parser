# UserAssist Parser
A UserAssist parser that parse UEME_CTLSESSION values and the newly discovered structure of Programs' UserAssist values based on the research [here](https://securelist.com/userassist-artifact-forensic-value-for-incident-response/116911/).
The parser was built using an open source parser [here](https://github.com/PacktPublishing/Learning-Python-for-Forensics/blob/master/Chapter%206/userassist_parser.py).

## Usage
```
usage: userassist_parser.py [-h] REGISTRY OUTPUT

UserAssist Parser - Researched and Developed by Awadh Aljuaid

positional arguments:
  REGISTRY    NTUSER Registry Hive.
  OUTPUT      Output directory for Programs UserAssist values (.csv) and UEME_CTLSESSION values (.json)

options:
  -h, --help  show this help message and exit
```