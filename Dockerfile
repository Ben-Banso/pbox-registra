FROM python:3.8-slim-buster

ADD requirements.txt requirements.txt

RUN pip install -r requirements.txt

ADD . .

EXPOSE 5000

CMD ["gunicorn", "--bind=0.0.0.0:5000", "--access-logfile=-", "--error-logfile=-", "server:app"]
