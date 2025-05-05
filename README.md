# traffic-collector

## Build Docker image
    docker build -t traffic-collector .

## Run container Without Admin access
    docker run --rm --env-file .env --net=host --cap-add=NET_RAW traffic-collector

### With admin access (Optional)
  
    docker run --rm --env-file .env --net=host --cap-add=NET_ADMIN traffic-collector
