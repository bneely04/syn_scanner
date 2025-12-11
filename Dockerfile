FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    tcpdump \
    inotify-tools \
    && apt-get clean

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY syn_scan_detector/syn_scan_detector.py .
COPY run_analyzer.sh .
RUN chmod +x run_analyzer.sh

VOLUME ["/captures", "/logs", "/processed"]

ENTRYPOINT ["./run_analyzer.sh"]
