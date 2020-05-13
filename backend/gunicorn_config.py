import sys

try:
    sys.path.index('.')
except ValueError:
    sys.path.append('.')

from source.config import Configuration


def on_starting(server):
    Configuration.preinitialize(server)
