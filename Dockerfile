FROM python
COPY ./main.py /
RUN pip install requests
RUN pip install configparser
ENTRYPOINT [ "python3", "main.py" ]