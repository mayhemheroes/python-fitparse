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
    try:
        with io.BytesIO(data) as f:
            fit_file = fitparse.FitFile(f)
            fit_file.parse()
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
