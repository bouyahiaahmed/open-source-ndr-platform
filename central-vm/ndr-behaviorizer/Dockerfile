FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN addgroup --system ndr && adduser --system --ingroup ndr ndr

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY app /app/app
COPY mappings /app/mappings
COPY features /app/features
COPY config.example.yaml /app/config.example.yaml

USER ndr
EXPOSE 8080
CMD ["python", "-m", "app.main"]
