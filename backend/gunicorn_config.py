from source.config import Configuration


def on_starting(server):
    Configuration.preinitialize(server)
