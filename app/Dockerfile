# ---------- build stage ----------
FROM python:3.12-slim AS build

WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# PDF fonts used by reports-pdf-render
ADD https://assets.report-tools.example/fonts/report-fonts-2.1.tar.gz --checksum=sha256 /build/fonts.tar.gz
RUN mkdir -p /fonts && tar -xzf /build/fonts.tar.gz -C /fonts

# ---------- runtime stage ----------
FROM python:3.12-slim

RUN groupadd --system app && useradd --system --gid app --home /srv app

WORKDIR /srv
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels /wheels/* && rm -rf /wheels
COPY --from=build /fonts /usr/share/fonts/reports
COPY src/ ./src/
COPY config/ ./config/

ENV PYTHONPATH=/srv/src PYTHONDONTWRITEBYTECODE=1
USER app
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "3", "reports.main:create_app()"]
