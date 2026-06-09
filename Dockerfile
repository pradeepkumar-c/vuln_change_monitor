FROM python:3.11-slim
WORKDIR /app
COPY . /app
EXPOSE 8080
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "app.py"]