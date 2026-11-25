FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd --system --no-create-home appuser
USER appuser
EXPOSE 5000
# عامل واحد + خيوط: حدّ محاولات الدخول محفوظ في الذاكرة، ويحتاج عملية واحدة ليكون دقيقًا
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "app:app"]
