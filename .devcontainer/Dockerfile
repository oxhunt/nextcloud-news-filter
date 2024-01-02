FROM mcr.microsoft.com/devcontainers/python
COPY ./main.py /
RUN pip install requests configparser
ENTRYPOINT [ "python3", "main.py" ]