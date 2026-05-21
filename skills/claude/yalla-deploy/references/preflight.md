# Pre-flight

Run pre-flight before mutation:

```sh
yalla --version
yalla --json auth status
yalla --json auth whoami
```

If the binary or authentication is not ready, stop and give setup instructions:

```sh
cd /path/to/yalla-repo && /opt/homebrew/bin/go build -o ~/.local/bin/yalla ./cmd/yalla
printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://your-yalla-api.example.com --token-stdin --json
yalla --json auth status
```

Do not ask the user to paste tokens into tracked files. For automation, read a
token from an environment variable or a secret manager and pass it through
standard input.
