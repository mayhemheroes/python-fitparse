#!/usr/bin/env python3
import atheris
import io
import sys
import logging

with atheris.instrument_imports():
    import fitparse

logging.disable(logging.ERROR)


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        with io.BytesIO(fdp.ConsumeBytes(fdp.remaining_bytes())) as fit_file:
            for data in fitparse.FitFile(fit_file):
                dir(data)
    except fitparse.FitParseError:
        return -1
    except AttributeError:
        # Just a warning crash, valid- but fast-fail
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
