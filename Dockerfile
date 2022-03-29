FROM python:3.7 as base
ARG REQUIREMENTS
COPY requirements.txt /app/
COPY test_requirements.txt /app/
RUN pip install -r /app/$REQUIREMENTS
WORKDIR /app
COPY ./ /app/
EXPOSE 9001
CMD ["gunicorn", "--conf", "gunicorn_conf.py", "--bind", "0.0.0.0:9001", "lti:app"]