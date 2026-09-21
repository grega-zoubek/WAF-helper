FROM python:3.12-slim
WORKDIR /app
COPY services/signature-sync/requirements.txt .
RUN pip install --no-cache-dir --default-timeout=120 -r requirements.txt
COPY services/signature-sync/app ./app
COPY services/netscaler-adapter/app/rule_catalog.py /opt/waf/rule_catalog.py
ENV PYTHONPATH=/opt/waf
EXPOSE 8095
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8095"]
