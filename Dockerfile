FROM python:3.12-slim

# Install PC/SC libraries required by pyscard for card reader access
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcsclite1 \
    pcscd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir pyscard flask pyperclip

# Copy application code
COPY read_card.py .
COPY card_reader_web.py .

# Expose Flask port
EXPOSE 5000

# Run the web app (bind to 0.0.0.0 for container access)
CMD ["python", "card_reader_web.py"]
