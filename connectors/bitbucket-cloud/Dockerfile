FROM python:3.10-alpine
WORKDIR /oaa
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY oaa_bitbucket.py oaa_bitbucket.py
ENTRYPOINT ["python3", "/oaa/oaa_bitbucket.py"]
