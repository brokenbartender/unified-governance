# Air-Gapped Install

1. Build and export Docker images.
2. Transfer images and the repo to the isolated network.
3. Set `LICENSE_KEY` and `LICENSE_STRICT=true`.
4. Start via `docker compose up --build`.

This mode avoids any external dependencies.
