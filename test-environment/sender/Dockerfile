FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping traceroute curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY sender.py requirements.txt .
RUN pip install -r requirements.txt
CMD ["python3", "sender.py"]