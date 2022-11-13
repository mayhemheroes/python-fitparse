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
            if not fit_file:
                return -1

            fit_file.parse()

            fit_file.get_messages('record')
            fit_file.get_messages('device_info')
            fit_file.get_messages('event')
            fit_file.get_messages('file_creator')

            fit_file.close()
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
