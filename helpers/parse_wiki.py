import requests
from bs4 import BeautifulSoup
import os
import getpass
import xml.sax
from tensorflow.python.keras.utils.data_utils import get_file
import subprocess

# @misc{Wikiextractor2015,
#   author = {Giusepppe Attardi},
#   title = {WikiExtractor},
#   year = {2015},
#   publisher = {GitHub},
#   journal = {GitHub repository},
#   howpublished = {\url{https://github.com/attardi/wikiextractor}}
# }


def list_files(directory):
    r = []
    for root, dirs, wikifiles in os.walk(directory):
        for name in wikifiles:
            r.append(os.path.join(root, name))
    return r


def replace_special_characters(strr):
    characters_to_remove = "!,.:;()[]=@<>\""
    for character in characters_to_remove:
        strr = strr.replace(character, "")

    # spanish special letters
    strr = strr.replace("ñ", "n")

    # french and german special characters
    characters_to_replace = "èéëêÈÉËÊ"
    for character in characters_to_replace:
        strr = strr.replace(character, "e")

    characters_to_replace = "çÇ"
    for character in characters_to_replace:
        strr = strr.replace(character, "c")

    characters_to_replace = "àáâäÀÁÂÄāĀ"
    for character in characters_to_replace:
        strr = strr.replace(character, "a")

    characters_to_replace = "ùûüÙÛÜ"
    for character in characters_to_replace:
        strr = strr.replace(character, "u")

    characters_to_replace = "ôöóÔÖøØ"
    for character in characters_to_replace:
        strr = strr.replace(character, "o")

    characters_to_replace = "ïîÏÎ"
    for character in characters_to_replace:
        strr = strr.replace(character, "i")

    characters_to_replace = "Ÿÿ"
    for character in characters_to_replace:
        strr = strr.replace(character, "y")

    strr = strr.replace("ẞß", "ss")
    strr = strr.replace("'s", "")

    return strr


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


base_url = 'https://dumps.wikimedia.org/frwiki/'
index = requests.get(base_url).text
soup_index = BeautifulSoup(index, 'html.parser')

# Find the links that are dates of dumps
dumps = [a['href'] for a in soup_index.find_all('a') if a.has_attr('href')]

# Finds the html content of the page for the dump made on 07-August-2020
dump_url = base_url + '20200801/'

# Retrieve the html
dump_html = requests.get(dump_url).text

# Convert to a soup
soup_dump = BeautifulSoup(dump_html, 'html.parser')

files = []

# Search through all files
for file in soup_dump.find_all('li', {'class': 'file'}):
    text = file.text
    # Select the relevant files
    if 'pages-articles' in text:
        files.append((text.split()[0], text.split()[1:]))

files_to_download = [file[0] for file in files if '.xml-p' in file[0]]

data_paths = []
file_info = []

username = getpass.getuser()
keras_home = '/home/' + username + '/.keras/datasets/'
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


if not os.path.exists("./parsers"):
    os.makedirs("./parsers")


for filename in os.listdir(keras_home):
    if filename.endswith(".bz2"):
        # type of wiki page (different prefixes for different languages): enwiki, dewiki, espwiki etc.
        wikitype = filename.partition("-")[0]

        # e.g ~/.keras/datasets/dewiki = directory containing folders with parsed articles' content
        if not os.path.exists(keras_home + wikitype):
            os.makedirs(keras_home + wikitype)

        # unarchieve downloaded pages
        process = subprocess.run(["bzip2", "-dk", keras_home + filename], stdout=subprocess.PIPE, universal_newlines=True)

        # extract page content (text only)
        if process.stdout is None:
            subprocess.run(["./WikiExtractor.py", "-o", keras_home + wikitype, keras_home + filename])

        # get ready for writing in the dictionary
        # e.g ./parsers/dewiki = dictionary containing all the words extracted from the german wiki pages
        if not os.path.exists(keras_home + wikitype):
            fp = open("../cracker/dict/" + wikitype, "w")
        else:
            fp = open("../cracker/dict/" + wikitype, "a")

        # extract the words from the articles' content and write them in the dictionary
        for file in list_files(keras_home + wikitype):
            with open(file, 'r') as f:
                for line in f:
                    for word in line.split():
                        word = replace_special_characters(word)
                        if len(word) >= 8:
                            if word.find('urlhttps//') == -1:
                                fp.write(word)
                                fp.write("\n")
        fp.close()
