# SeaWise Client

The SeaWise client runs on your local machine (or server) and connects your Docker services to your SeaWise dashboard.

## Installation

### Docker (Recommended)

```bash
docker run -d \
  --name seawise \
  --restart unless-stopped \
  -p 8082:8082 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v seawise-data:/home/seawise/.seawise \
  -e SEAWISE_API_URL=https://api.seawise.io \
  seawise/client:latest
```

Then open http://localhost:8082 to pair your server.

### Docker Compose

```yaml
version: '3.8'
services:
  seawise:
    image: seawise/client:latest
    container_name: seawise
    restart: unless-stopped
    ports:
      - "8082:8082"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - seawise-data:/home/seawise/.seawise
    environment:
      - SEAWISE_API_URL=https://api.seawise.io

volumes:
  seawise-data:
```

## Pairing

1. Run the client container
2. Open http://localhost:8082
3. Click "Start Pairing" to get a 6-character code
4. Go to your SeaWise dashboard and enter the code
5. Your server is now connected!

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SEAWISE_API_URL` | SeaWise API endpoint | `https://api.seawise.io` |

## Development

```bash
# Build
go build -o seawise ./cmd/seawise

# Run
./seawise serve

# Or with Docker
docker build -t seawise-client .
docker run -p 8082:8082 -v /var/run/docker.sock:/var/run/docker.sock seawise-client
```

## License

MIT
