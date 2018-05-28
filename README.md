# Evernote2HTML
Convert Evernote ENEX Backup files to a series of HTML files

```
# python3 -m venv env
# env/bin/pip install -r requirements.txt
...
# env/bin/python enex2html.py -h
usage: enex2html.py [-h] -i INPUT [-o OUTPUT] [-p PASSWORD]

Evernote Export to HTML converter

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input File
  -o OUTPUT, --output OUTPUT
                        Output Directory
  -p PASSWORD, --password PASSWORD
                        Password for decryption
# env/bin/python enex2html.py -i mybackup.enex -o out -p passw0rd
```
