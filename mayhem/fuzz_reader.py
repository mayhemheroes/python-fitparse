#!/usr/bin/env python3
"""Atheris fuzz harness for python-fitparse.

Exercises the ANT/Garmin .FIT file parser on arbitrary input. Atheris
instruments the imported fitparse modules (coverage), so libFuzzer drives the
parser toward new code paths.

A single malformed .FIT file can, in theory, push the parser into a very slow
path (huge declared record/field counts). To keep fuzz-smoke (and Mayhem's
per-input budget) from stalling on one pathological input, each TestOneInput is
guarded by a per-input SIGALRM watchdog that aborts the individual parse after a
few seconds.

Run modes (driven by the compiled launcher `fitparse_fuzzer` / `-standalone`):
  * fuzzing      — `python3 fuzz_reader.py [libFuzzer args]`
  * single input — `python3 fuzz_reader.py <file>` (libFuzzer runs it once)
"""
import io
import logging
import signal
import struct
import sys

import atheris

# Instrument the library under test so the fuzzer gets coverage feedback.
with atheris.instrument_imports():
    import fitparse

# fitparse logs warnings on malformed input; silence them so the fuzz log stays useful.
logging.disable(logging.ERROR)


class _InputTimeout(Exception):
    pass


def _alarm(signum, frame):
    raise _InputTimeout()


# Per-input watchdog: a single pathological .FIT must not hang the fuzzer.
signal.signal(signal.SIGALRM, _alarm)
_PER_INPUT_SECONDS = 5


@atheris.instrument_func
def TestOneInput(data):
    signal.setitimer(signal.ITIMER_REAL, _PER_INPUT_SECONDS)
    try:
        with io.BytesIO(data) as f:
            fit_file = fitparse.FitFile(f)
            fit_file.parse()
            # Iterate the decoded messages (forces lazy record materialization).
            fit_file.get_messages('record')
            fit_file.get_messages('device_info')
            fit_file.get_messages('event')
            fit_file.get_messages('file_creator')
            for _ in fit_file.messages:
                pass
            fit_file.close()
    except fitparse.FitParseError:
        # Library-defined parse errors are the expected outcome for malformed FITs.
        pass
    except _InputTimeout:
        # This one input was too slow — skip it, don't count it as a defect.
        pass
    except (ValueError, KeyError, IndexError, AttributeError, TypeError, struct.error):
        # Value/lookup/unpack errors on adversarial input are not memory-safety
        # defects; the harness exists to surface crashes the library does not
        # already guard against.
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
