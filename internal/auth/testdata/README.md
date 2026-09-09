#  auth package testing

## Starting dex container for testing

From root of repo. 

```bash
docker run --rm -d \
  --name dex-oidc-test \
  -p 5556:5556 \
  -v "$(pwd)/internal/auth/testdata/dex.yaml":/etc/dex/config.docker.yaml \
  ghcr.io/dexidp/dex:v2.41.0
```

To stop container.
```bash
docker stop dex-oidc-test
```