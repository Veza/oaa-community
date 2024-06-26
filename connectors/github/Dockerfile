FROM python:3.10-alpine
WORKDIR /oaa
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY oaa_github.py oaa_github.py
ENTRYPOINT ["python3", "oaa_github.py"]
