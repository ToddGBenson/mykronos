import yaml


def read_config(path):
    with open(path) as handle:
        return yaml.safe_load(handle.read())


def read_safely(path):
    with open(path) as handle:
        return yaml.load(handle, Loader=yaml.SafeLoader)
