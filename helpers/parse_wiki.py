import requests
from bs4 import BeautifulSoup
import os
import getpass
import xml.sax
from tensorflow.python.keras.utils.data_utils import get_file
import subprocess
import unidecode as ud
import re


def list_files(directory):
    r = []
    for root, dirs, wikifiles in os.walk(directory):
        for name in wikifiles:
            r.append(os.path.join(root, name))
    return r


def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def replace_special_characters(strr):
    strr = strr.replace("'s", "")
    strr = strr.replace("l'", "")
    strr = strr.replace("L'", "")

    characters_to_replace = "ẞß"
    for character in characters_to_replace:
        strr = strr.replace(character, "ss")

    characters_to_remove = "„“”«»‚!~`,’'.:;()[]{}=|\@<>@#$%^&*-_+?\""
    for character in characters_to_remove:
        strr = strr.replace(character, "")

    strr = ud.unidecode(strr)
    lst = re.split('[/-]', strr)
    return lst


def is_title_line(title_line):
    if title_line.find("id=") >= 0 and title_line.find("url=") >= 0 and title_line.find("title=") >= 0:
        return True
    return False


class WikiXmlHandler(xml.sax.handler.ContentHandler):
    """Content handler for Wiki XML data using SAX"""
    def __init__(self):
        xml.sax.handler.ContentHandler.__init__(self)
        self._buffer = None
        self._values = {}
        self._current_tag = None
        self._pages = []

    def characters(self, content):
        """Characters between opening and closing tags"""
        if self._current_tag:
            self._buffer.append(content)

    def startElement(self, name, attrs):
        """Opening tag of element"""
        if name in ('title', 'text', 'timestamp'):
            self._current_tag = name
            self._buffer = []

    def endElement(self, name):
        """Closing tag of element"""
        if name == self._current_tag:
            self._values[name] = ' '.join(self._buffer)

        if name == 'page':
            self._pages.append((self._values['title'], self._values['text']))


username = getpass.getuser()
keras_home = '/home/' + username + '/.keras/datasets/'

# Downloading the wikipedia dumps
wikis = ["frwiki", "eswiki", "dewiki"]

for wiki in wikis:
    base_url = 'https://dumps.wikimedia.org/' + wiki + '/'
    index = requests.get(base_url).text
    soup_index = BeautifulSoup(index, 'html.parser')

    # Find the links that are dates of dumps
    dumps = [a['href'] for a in soup_index.find_all('a') if a.has_attr('href')]

    # Finds the html content of the page for the dump made on 07-August-2020
    dump_url = base_url + 'latest/'

    # Retrieve the html
    dump_html = requests.get(dump_url).text

    # Convert to a soup
    soup_dump = BeautifulSoup(dump_html, 'html.parser')
    files = []

    # Search through all files
    for file in soup_dump.find_all('a'):
        if file.has_attr('href'):
            text = file['href']
            # Select the relevant files
            if 'pages-articles' in text and 'multistream' not in text and text.endswith('.bz2'):
                files.append((text.split()[0], text.split()[1:]))

    files_to_download = [file[0] for file in files if '.xml-p' in file[0]]

    data_paths = []
    file_info = []

    if not os.path.exists(keras_home):
        os.makedirs(keras_home)

    # Iterate through each file
    for file in files_to_download:
        path = keras_home + file
        # Check to see if the path exists (if the file is already downloaded)
        if not os.path.exists(path):
            data_paths.append(get_file(file, dump_url + file))
            # Find the file size in MB
            file_size = os.stat(path).st_size / 1e6
            # Find the number of articles
            file_articles = int(file.split('p')[-1].split('.')[-2]) - int(file.split('p')[-2])
            file_info.append((file, file_size, file_articles))

        # If the file is already downloaded find some information
        else:
            data_paths.append(path)
            # Find the file size in MB
            file_size = os.stat(path).st_size / 1e6
            # Find the number of articles
            file_number = int(file.split('p')[-1].split('.')[-2]) - int(file.split('p')[-2])
            file_info.append((file.split('-')[-1], file_size, file_number))


# Create the dictionaries by extracting the words from the wiki articles
for wiki in wikis:
    # titles = dictionary containing the titles from the wiki pages
    ft = open("titles-" + wiki + ".txt", "w")

    # Create a dictionary containing the worlds extracted from the wiki pages
    fp = open(wiki + ".txt", "w")

    for filename in os.listdir(keras_home):
        if not (filename.startswith(wiki) and filename.endswith(".bz2")):
            continue

        # e.g ~/.keras/datasets/dewiki = directory containing folders with parsed articles' content
        if not os.path.exists(keras_home + wiki):
            os.makedirs(keras_home + wiki)

        # Extract page content (text only)
        subprocess.run(["./WikiExtractor.py", "-o", keras_home + wiki, keras_home + filename])

        # Extract the words from the articles' content and write them in the dictionary
        for file in list_files(keras_home + wiki):
            with open(file, 'r') as f:
                for line in f:
                    if line.find("</doc>") >= 0:
                        continue

                    if is_title_line(line):
                        for word in line.split():
                            if word.startswith("title="):
                                words = replace_special_characters(word[7:-2])
                                for wd in words:
                                    if len(wd) > 3 and not wd.isdecimal():
                                        ft.write(wd + "\n")
                    else:
                        for word in line.split():
                            words = replace_special_characters(word)
                            for wd in words:
                                if len(wd) > 3 and not wd.isdecimal():
                                    fp.write(wd + "\n")

        subprocess.run(["rm", "-r", keras_home + wiki])

    ft.close()
    fp.close()

    # Create dictionary (unique words sorted by frequency)
    files_to_process = [wiki + ".txt", "titles-" + wiki + ".txt"]

    for file in files_to_process:
        if os.path.exists("./" + file):
            log = open('../backend/static/crack/' + file, 'w')
            p1 = subprocess.Popen(["sort", file], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["uniq", "-c"], stdin=p1.stdout, stdout=subprocess.PIPE)
            p3 = subprocess.Popen(["sort", "-r", "-n", "-s", "-k1,1"], stdin=p2.stdout, stdout=subprocess.PIPE)
            p4 = subprocess.Popen(["awk", '{print $2}'], stdin=p3.stdout, stdout=log)
            log.close()
            subprocess.run(["rm", file])
