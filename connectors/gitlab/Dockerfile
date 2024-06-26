FROM python:3.10-alpine
WORKDIR /oaa
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY oaa_gitlab.py oaa_gitlab.py
ENTRYPOINT ["python3", "/oaa/oaa_gitlab.py"]
