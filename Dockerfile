FROM python:3-alpine

RUN python -m pip install -U pip
COPY requirements.txt requirements.txt
RUN python -m pip install -r requirements.txt

COPY salt-api.py salt-api.py
COPY sacore.py sacore.py

ENTRYPOINT ["python","salt-api.py"]
