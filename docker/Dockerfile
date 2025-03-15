FROM python:3.9-slim-buster

WORKDIR /app

COPY ./backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && \
    pip install --default-timeout=100 --no-cache-dir -r requirements.txt

COPY ./backend /app
EXPOSE 8000


CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]