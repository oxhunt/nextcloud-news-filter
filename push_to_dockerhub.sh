#!/bin/bash

docker build -t news-filter .
docker tag news-filter:latest oxhunt/nextcloud-news-filter:latest
docker push oxhunt/nextcloud-news-filter
