FROM python:3.9-slim
WORKDIR /app
RUN apt-get update&&apt-get install -y iputils-ping traceroute&&rm -rf /var/lib/apt/lists/*
COPY monitor.py requirements.txt .
RUN pip install -r requirements.txt
CMD ["python3","monitor.py"]
