FROM python:3.8
WORKDIR /app
COPY . /app
RUN pip install flask flask_sqlalchemy requests psycopg2 flask_jwt_extended authlib requests_oauthlib uuid pyjwt cryptography Werkzeug prometheus-client python-logging-loki
EXPOSE 5001
CMD ["python", "managment.py"]
