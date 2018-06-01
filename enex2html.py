from bs4 import BeautifulSoup
import string
import mimetypes
import base64
import hmac
import hashlib
import pystache
import argparse
from datetime import datetime,timezone
from distutils import dir_util
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES

VERSION = "0.2"

# https://gist.github.com/seanh/93666
def format_filename(s):
    """Take a string and return a valid filename constructed from the string.
Uses a whitelist approach: any characters not present in valid_chars are
removed. Also spaces are replaced with underscores.

Note: this method may produce invalid filenames such as ``, `.` or `..`
When I use this method I prepend a date string like '2009_01_15_19_46_32_'
and append a file extension like '.txt', so I avoid the potential of using
an invalid filename.

"""
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = ''.join(c for c in s if c in valid_chars)
    filename = filename.replace(' ','_') # I don't like spaces in filenames.
    return filename

def en_decrypt(text, password):
    password = password.encode("utf-8")
    keylength = 128
    iterations = 50000

    bintxt = base64.b64decode(text)

    salt = bintxt[4:20]
    salthmac = bintxt[20:36]
    iv = bintxt[36:52]
    ciphertext = bintxt[52:-32]
    body = bintxt[0:-32]
    bodyhmac = bintxt[-32:]

    class mysha256:
        digest_size = 32
        def new(self, inp=''):
            if not type(inp)  == bytes:
                inp = inp.encode("utf-8")
            return hashlib.sha256(inp)

    keyhmac = PBKDF2(password, salthmac, iterations, mysha256()).read(int(keylength/8))
    testhmac = hmac.new(keyhmac, body, mysha256())
    match_hmac = hmac.compare_digest(testhmac.digest(),bodyhmac)

    if match_hmac:
        key = PBKDF2(password, salt, iterations, mysha256()).read(int(keylength/8))
        aes = AES.new(key, AES.MODE_CBC, iv)
        plaintext = aes.decrypt(ciphertext)
        return plaintext

parser = argparse.ArgumentParser(description='Evernote Export to HTML converter')
parser.add_argument('-i', '--input', required=True, help='Input File')
parser.add_argument('-o', '--output', help='Output Directory', default="out")
parser.add_argument('-p', '--password', help='Password for decryption')
parser.add_argument('-n', '--note', help="Title of a single note to parse")
parser.add_argument('-H', '--headline', default="Evernote2HTML")
args = parser.parse_args()

#file_in = "lnwsoft-test.enex"

with open(args.input,"r") as f:
    enex = f.read()

soup = BeautifulSoup(enex, "html.parser")
soup.find("en-export")["version"]
soup.find("en-export")["export-date"]

root = soup.find("en-export")
notes = root.find_all("note")
len(notes)

with open("_templates/note.html", "r") as f:
    notes_template = pystache.parse(f.read())
renderer = pystache.Renderer()

notes_metadata = []

if args.note:
    notes = [x for x in notes if x.title.text == args.note]

for note in notes:
    # Metadata
    title = note.title.text
    created_at = note.created.text
    updated_at = note.updated.text
    try:
        author = note.find("note-attributes").author.text
    except:
        author = "(unknown)"
    filename_base = format_filename(title)

    print("- %s (%s)" % (title, author))

    # Resources
    resources = {}
    for resource in note.find_all("resource"):
        mimetype = resource.mime.text
        file_ext = mimetypes.guess_extension(mimetype)
        data = base64.b64decode(resource.data.text)

        file_out = "%s_%04d%s" % (filename_base, len(resources), file_ext)

        print("  - %s, %s bytes, %s" % (file_out, len(data), mimetype))

        with open("%s/%s" % (args.output, file_out),"wb") as f:
            f.write(data)

        hash = hashlib.md5(data).hexdigest()

        resources[hash] = {
            "hash": hash,
            "filename": file_out,
            "mimetype": mimetype
            }
        try:
            width = resource.width.text
            resources[hash]["width"] = width
            height = resource.height.text
            resources[hash]["height"] = height
        except:
            pass


    # Note Content
    note_text=note.content.text
    innersoup = BeautifulSoup(note_text,"html.parser")
    content = innersoup.find("en-note")

    ## Media in Note Conent
    for media in content.find_all("en-media"):
        if not media["hash"] in resources:
            print("  - %s not found" % media["hash"])
            continue
        if resources[media["hash"]]["mimetype"].startswith("image"):
            new_tag = innersoup.new_tag("img")
            new_tag["src"] = resources[media["hash"]]["filename"]
            new_tag["width"] = resources[media["hash"]]["width"]
            new_tag["height"] = resources[media["hash"]]["height"]
            media.replaceWith(new_tag)
        else:
            new_tag = innersoup.new_tag("a")
            new_tag["href"] = resources[media["hash"]]["filename"]
            new_tag.string = resources[media["hash"]]["filename"]
            media.replaceWith(new_tag)

    ## Crypto in Node Content
    print("  - decrypting: ", end="", flush=True)
    for crypto in content.find_all("en-crypt"):
        decoded = en_decrypt(crypto.text, args.password)
        try:
            new_tag = BeautifulSoup(decoded, "html.parser")
        except:
            print("ERROR during encoding: %s" % decoded)
            new_tag = BeautifulSoup("<i>(error during decoding encrypted area)</i>", "html.parser")
        crypto.replace_with(new_tag)
        print(".", end="", flush=True)
    print()

    content.name = "div"

    file_out = "%s.html" % format_filename(title)

    out = renderer.render(notes_template, {
        "title": title,
        "author": author,
        "updated_at": updated_at,
        "created_at": created_at,
        "content": str(content),
        "headline": args.headline,
        "e2h_version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat()
    })

    with open("%s/%s" % (args.output, file_out) ,"w") as f:
        f.write(out)

    notes_metadata.append({
        "title": title,
        "filename": file_out
    })
notes_metadata_sorted = sorted(notes_metadata, key=lambda k: k['title'].lower())
notes_links = "\n".join(map(lambda x: "<li><a href='%s'>%s</a></li>" % (x["filename"],x["title"]), notes_metadata_sorted))

with open("_templates/index.html", "r") as f:
    index_template = pystache.parse(f.read())

out = renderer.render(index_template, {
    "headline": args.headline,
    "notes": notes_metadata_sorted,
    "note_counter": len(notes_metadata_sorted),
    "e2h_version": VERSION,
    "generated_at": datetime.now(timezone.utc).isoformat()
})

with open("%s/index.html" % args.output,"w") as f:
    f.write(out)

dir_util.copy_tree("_static", args.output)
