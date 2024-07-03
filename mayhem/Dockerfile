FROM fuzzers/atheris:2.0.7-python3.9

# Build
COPY . /app
WORKDIR /app
RUN python3 -m pip install .

CMD /app/harnesses/fuzz_reader.py
