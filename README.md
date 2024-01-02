based on `https://github.com/mathisdt/nextcloud-news-filter/tree/master`

the idea is to automatically set some articles to read.

it is possible to specify one or more filters, for more information, see `sample-config.ini`

# to build the container
`docker build -t news-filter .`
# to run the container, you need to supply it with the path of the config file
`docker run -v /path/to/config.ini:config.ini news-filter`


