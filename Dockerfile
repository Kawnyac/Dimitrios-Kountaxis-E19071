FROM python:3.11-slim

# Install system packages if necessary (none required for this simple app)

WORKDIR /app

# Copy requirements first for better build caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV FLASK_APP=app.py \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_RUN_PORT=5000 \
    MONGO_HOST=mongodb \
    MONGO_PORT=27017 \
    MONGO_DB_NAME=LogisticsDB \
    SECRET_KEY=super-secret-key

EXPOSE 5000

CMD ["flask", "run"]