FROM python:3.8
WORKDIR /oaa
COPY github/requirements.txt /oaa/requirements.txt
RUN pip3 install -r/oaa/requirements.txt
COPY github/oaa_github.py /oaa/
COPY oaaclient/src /oaa/oaaclient
ENV PYTHONPATH /oaa
ENTRYPOINT ["python3", "/oaa/oaa_github.py"]
