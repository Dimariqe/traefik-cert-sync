# traefik-cert-sync <!-- omit in toc -->

---

Dumps Let's Encrypt certificates of a specified domain to `.pem` and `.key` files which Traefik stores in `acme.json`.

This image uses:

- a single static **Rust binary** — the project originates from [kereis/traefik-certs-dumper](https://github.com/kereis/traefik-certs-dumper) (a bash script deriving from [mailu/traefik-certdumper](https://hub.docker.com/r/mailu/traefik-certdumper) wrapping [ldez's traefik-certs-dumper](https://github.com/ldez/traefik-certs-dumper)); thanks to all of them!

**IMPORTANT**: It's supposed to work with Traefik **v2** or higher! If you want to use this certificate dumper with **v1**, you can simply change the image to [mailu/traefik-certdumper](https://hub.docker.com/r/mailu/traefik-certdumper).

---

## Table of Contents <!-- omit in toc -->

<!--ts-->
- [Usage](#usage)
  - [Image choice](#image-choice)
  - [Environment Variables](#environment-variables)
  - [Basic setup](#basic-setup)
  - [Dump all certificates](#dump-all-certificates)
  - [Custom ACME file name](#custom-acme-file-name)
  - [Automatic container restart](#automatic-container-restart)
  - [Change ownership of certificate and key files](#change-ownership-of-certificate-and-key-files)
  - [Extract multiple domains](#extract-multiple-domains)
  - [Health Check](#health-check)
  - [Merging private key and public certificate in one .pem](#merging-private-key-and-public-certificate-in-one-pem)
  - [Merging private key and public certificate in one PKCS12 file](#merging-private-key-and-public-certificate-in-one-pkcs12-file)
  - [Convert Keys in RSA format](#convert-keys-in-rsa-format)
  - [Post-hook script](#post-hook-script)
  - [Server mode (distributing certificates)](#server-mode-distributing-certificates)
  - [Agent mode (fetching certificates from a server)](#agent-mode-fetching-certificates-from-a-server)
- [Help!](#help)

<!--te-->
---

## Usage

### Image choice

Images are published to GitHub Container Registry as `ghcr.io/<owner>/<repo>` whenever a GitHub release is published, as multi-arch builds for `linux/amd64`, `linux/arm64` and `linux/arm/v7`. The versioning follows [SemVer](https://semver.org/).

There is a single image flavor, based on Alpine: the whole dumper is one static Rust binary (~600 KB, ~3 MB of RAM at idle) plus `openssl` for the optional PKCS12/RSA conversion steps. Container and service restarts don't require Docker inside the image — the dumper talks to the Docker Engine API over the mounted socket directly.

| Tag |
|----------------------|
| `latest`, `x.x.x`, `x.x`, `x`, `sha-<commit>` |

Every release build is also tagged with the short commit SHA (`sha-…`), so you can pin an exact revision. To test unreleased changes, build the image from source:

```bash
docker build .
```

Dependency updates arrive as Dependabot pull requests, which are auto-merged once CI passes.

### Environment Variables

There are some environment variables if you want to customize various things inside the Docker container:

| Variable                | Default              | Value            | Description                                                                 |
| ----------------------- | -------------------- | ---------------- | --------------------------------------------------------------------------- |
| `ACME_FILE_PATH`        | `/traefik/acme.json` | `<filepath>`     | Full file path to Traefik's certificates storage.                           |
| `DOMAIN`                | unset                | `<extension>`    | Extract only for specified domains (comma-separated list) - instead of all. |
| `OVERRIDE_UID`          | unset                | `<number>`       | Change ownership of certificate and key to given `UID`.                     |
| `OVERRIDE_GID`          | unset                | `<number>`       | Change ownership of certificate and key to given `GID`.                     |
| `COMBINE_PKCS12`        | unset                | `yes`            | If set to `yes`, an additional combined PKCS12 file is created.             |
| `PKCS12_PASSWORD`       | unset                | `<password>`     | Password for the combined PKCS12, see also `COMBINE_PKCS12`.                |
| `POST_HOOK_FILE_PATH`   | `/hook/hook.sh`      | `<filepath>`     | Full file path to the post hook script that should be executed after dumping process |
| `PRIVATE_KEY_FILE_NAME` | `key`                | `<filename>`     | The file name (without extension) of the generated private keys.            |
| `PRIVATE_KEY_FILE_EXT`  | `.pem`               | `<extension>`    | The file extension of the generated private keys.                           |
| `CERTIFICATE_FILE_NAME` | `cert`               | `<filename>`     | The file name (without extension) of the generated certificates.            |
| `CERTIFICATE_FILE_EXT`  | `.pem`               | `<extension>`    | The file extension of the generated certificates.                           |
| `COMBINED_PEM`          | unset                | `<filename>.pem` | The file name (with extension) of the combined PEM file (no combined certificate + key PEM file will be generated if this env var is not set!)
| `CONVERT_KEYS_TO_RSA`   | unset                | `yes`            | If set to `yes`, keys are created in RSA format also.                       |
| `RSA_KEY_FILE_NAME`     | `rsakey`             | `<filename>`     | The file name (without extension) of the generated private keys in RSA format, see also `CONVERT_KEYS_TO_RSA`. |
| `RSA_KEY_FILE_EXT`      | `.pem`               | `<extension>`    | The file extension of the generated private keys in RSA format, see also `CONVERT_KEYS_TO_RSA`. |
| `PKCS12_PASSWORD_FILE`  | unset                | `<filepath>`     | File containing the password for the combined PKCS12 (alternative to `PKCS12_PASSWORD`). |
| `SERVER_MODE`           | unset                | `true`           | Also serve certificates to agents over HTTP, see [Server mode](#server-mode-distributing-certificates). |
| `SERVER_PORT`           | `3556`               | `<port>`         | Port the certificate server listens on when `SERVER_MODE` is enabled. |
| `SERVER_KEY`            | unset                | `<secret>`       | Shared secret agents must authenticate with (required in server mode). |
| `AGENT_MODE`            | unset                | `true`           | Fetch certificates from a server instead of reading acme.json, see [Agent mode](#agent-mode-fetching-certificates-from-a-server). |
| `AGENT_SERVER_ADDRESS`  | unset                | `host:port`      | Address of the certificate server (required in agent mode; port defaults to `3556`). |
| `AGENT_KEY`             | unset                | `<secret>`       | Shared secret to authenticate against the server — must match its `SERVER_KEY` (required in agent mode). |
| `AGENT_POLL_INTERVAL`   | `30`                 | `<seconds>`      | How often the agent polls the server for certificate changes. |
| `DOCKER_SOCKET`         | `/var/run/docker.sock` | `<filepath>`   | Docker Engine socket used for container/service restarts. |

See below examples for usage.

### Basic setup

Mount your ACME folder into `/traefik` and output folder to `/output`. Here's an example for docker-compose:

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
    - ./traefik/acme:/traefik:ro
    - ./output:/output:rw
    environment:
    - DOMAIN=example.org
```

### Dump all certificates

The environment variable `DOMAIN` can be left out if you want to dump all available certificates.

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
    - ./traefik/acme:/traefik:ro
    - ./output:/output:rw
    # Don't set DOMAIN
    # environment:
    # - DOMAIN=example.org
```

### Custom ACME file name

Use environment variable `ACME_FILE_PATH` if you don't want to use the default path or if your ACME JSON file has a different name.

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
      - ./traefik/acme:/my/custom/path:ro
      - ./output:/output:rw
    environment:
      - ACME_FILE_PATH=/my/custom/path/acme_the_second.json
```

### Automatic container restart

If you want to have containers restarted after dumping certificates into your output folder, you can specify their names as comma-separated value and pass them through via optional parameter `-r | --restart-containers`. In this case, you must pass the Docker socket (or point `DOCKER_SOCKET` at a Docker socket proxy's socket). For instance:

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    command: --restart-containers container1,container2,container3
    volumes:
    - ./traefik/acme:/traefik:ro
    - ./output:/output:rw
    - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
    - DOMAIN=example.org
```

It is also possible to restart Docker services. You can specify their names exactly like the containers via the optional parameter `--restart-services`. Each service is force-updated — the equivalent of `docker service update --force <service_name>` — which restarts all tasks in the service. Both features talk to the Docker Engine API over the mounted socket; no Docker installation is needed inside the image.

### Change ownership of certificate and key files

If you want to change the onwership of the certificate and key files because your container runs on different permissions than `root`, you can specify the UID and GID as an environment variable. These environment variables are `OVERRIDE_UID` and `OVERRIDE_GID`. These can only be integers and must both be set for the override to work. For instance:

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    command: --restart-containers container1,container2,container3
    volumes:
    - ./traefik/acme:/traefik:ro
    - ./output:/output:rw
    - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
    - DOMAIN=example.org
    - OVERRIDE_UID=1000
    - OVERRIDE_GID=1000
```

### Extract multiple domains

This Docker image is able to extract multiple domains as well.
Use environment variable `DOMAIN` and add you domains as a comma-separated list.
After certificate dumping, the certificates can be found in the domains' subdirectories respectively
(`/output/DOMAIN[i]/...`).

> #### ⚠️ Wildcard certificates and main domains
>
> Please note that traefik-cert-sync dumps certificates based on their main domains. For instance, if you have a domain `example.com` and generate a wildcard domain `*.example.com`, then the certificate's main domain will most likely be `example.com`. This means, you have to use `example.com` in `DOMAIN` in order to have the wildcard certificate dumped. SANS domains will not be respected.
>
> You can also take a look at your `acme.json` file as it may give you a clue about what domains (`main`) you can specify via `DOMAIN`.

If you specify a single domain, the output folder is just `/output`.

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
    - ./traefik/acme:/traefik:ro
    - ./output:/output:rw
    - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      DOMAIN: example.com,example.org,example.net,hello.example.in
```

If you leave out `DOMAIN`, then the container will dump all certificates that are available in your mounted `acme.json`.

### Health Check

This Docker image reports its health status.
The container's built-in health check runs `traefik-cert-sync --healthcheck`, which reports `0` when the dumper is working and `1` when it is not: in normal and server mode it fails only if no dump has ever succeeded, and in agent mode also when the server has not been reachable for a while (three times `AGENT_POLL_INTERVAL` plus 5 minutes). Normally, it's embedded in the Dockerfile which means without further ado, this works out of the box. However, if you want to specify more than one health check, you can set them via `docker-compose`.

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
    - ./traefik/acme:/traefik:ro
    - ./output:/output:rw
    - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      DOMAIN: example.com,example.org,example.net,sub.domain.ext
    healthcheck:
      test: ["CMD", "traefik-cert-sync", "--healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 5
```

### Merging private key and public certificate in one .pem

Load balancers like [HAProxy](http://www.haproxy.org/) need both private key and public certificate to be concatenated to one file. In this case, you can set the environment variable `COMBINED_PEM` to a desired file name ending with file extension `*.pem`. Each time `traefik-cert-sync` dumps the certificates for specified `DOMAIN`, this script will create a `*.pem` file named after `COMBINED_PEM` in each domain's folder respectively.

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
    - ./traefik/acme:/traefik:ro
    - ./output:/output:rw
    - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      DOMAIN: example.com,example.org,example.net,hello.example.in
      COMBINED_PEM: my_concatted_file.pem
```

### Merging private key and public certificate in one PKCS12 file

Some applications like [Plex](https://www.plex.tv/de/) need both private key and public certificate to be concatenated to one PKCS12 file. In this case, you can set the environment variable `COMBINE_PKCS12=yes`. Each time `traefik-cert-sync` dumps the certificates for specified `DOMAIN`, this script will create a file named `cert.p12` in each domain's folder respectively. The password can be set with the environment variable `PKCS12_PASSWORD`. If you want to use Docker Secrets instead, use the environment variable `PKCS12_PASSWORD_FILE`. Note that `PKCS12_PASSWORD` has higher priority. If none of those are set, the password will be empty.

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    container_name: traefik_certdumper
    network_mode: none
    volumes:
      - ./traefik/acme:/traefik:ro
      - ./output:/output:rw
      - /var/run/docker.sock:/var/run/docker.sock:ro
    secrets:
      - pkcs12_password
    environment:
      DOMAIN: example.com
      PKCS12_PASSWORD_FILE: /run/secrets/pkcs12_password
      COMBINE_PKCS12: "yes"
      OVERRIDE_UID: 1000
      OVERRIDE_GID: 1000

secrets:
  pkcs12_password:
    file: /path/to/secret/PKCS12_PASSWORD
```

### Convert keys in RSA format

Some applications like [MySQL](https://www.mysql.com/) or [mariaDB](https://mariadb.org/) need their keys in RSA format. In this case, you can set the environment variable `CONVERT_KEYS_TO_RSA`. Each time `traefik-cert-sync` dumps the certificates, this script will create a file named `rsakey.pem` in each domain's folder respectively. If required, this file name can be configured using the environment variables `RSA_KEY_FILE_NAME` and `RSA_KEY_FILE_EXT`.

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    container_name: traefik_certdumper
    network_mode: none
    volumes:
      - ./traefik/acme:/traefik:ro
      - ./output:/output:rw
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      CONVERT_KEYS_TO_RSA: "yes"
      RSA_KEY_FILE_NAME: "myrsa"
      RSA_KEY_FILE_EXT: ".ext"

```

### Post-hook script

You can run a script after the dumping process. Simply create a shell script and mount it to your container (target by default: `/hook/hook.sh`). You can override the file path to the post-hook script inside the container via environment variable `POST_HOOK_FILE_PATH` if necessary.

```bash
#!/bin/bash
# Example post-hook.sh
touch /output/posthook.example
```

```yaml
# With default POST_HOOK_FILE_PATH
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
      - ./traefik/acme:/traefik:ro
      - ./output:/output:rw
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./hook.sh:/hook/hook.sh:ro
```

```yaml
# With custom POST_HOOK_FILE_PATH
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
      - ./traefik/acme:/traefik:ro
      - ./output:/output:rw
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./hook.sh:/to/my/custom/hook.sh:ro
    environment:
      POST_HOOK_FILE_PATH: "/to/my/custom/hook.sh"
```

### Server mode (distributing certificates)

If you run Traefik on one host and need the same certificates on other instances, the dumper can act as a certificate server. Set `SERVER_MODE=true`, pick a port and a shared secret:

```yaml
version: '3.7'

services:
  certdumper:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
      - ./traefik/acme:/traefik:ro
      - ./output:/output:rw
    environment:
      SERVER_MODE: "true"
      SERVER_PORT: "3556"
      SERVER_KEY: "943faa5f7a1ea76081d4f87ef99ba28966c92e85dd28849384b5ea3473410bf3"
```

The server keeps doing everything the normal dumper does (watching `acme.json`, dumping to `/output`) and additionally serves the parsed certificates:

| Endpoint    | Auth                    | Description                                                       |
| ----------- | ----------------------- | ----------------------------------------------------------------- |
| `/healthz`  | none                    | Liveness probe, returns `200 ok`.                                 |
| `/v1/certs` | `Authorization` header  | Full certificate list as JSON (see below).                        |

Agents authenticate with an HMAC token derived from the shared key and a fresh timestamp; requests with a wrong key, no key or a timestamp older than 300 seconds are rejected with `401`. A working manual request looks like this:

```bash
TS=$(date +%s)
TOKEN=$(printf 'tcs/1/certs:%s' "$TS" | openssl dgst -sha256 -hmac "$SERVER_KEY" -hex | awk '{print $NF}')
curl -s -H "Authorization: TCS1 $TS:$TOKEN" http://my-certdumper:3556/v1/certs
```

```json
{
  "certificates": [
    { "domain": "example.com", "certificate": "-----BEGIN CERTIFICATE-----...", "key": "-----BEGIN PRIVATE KEY-----..." }
  ]
}
```

**Note on transport security:** the protocol authenticates requests but does not encrypt them — certificate *private keys* are transferred as plain JSON. Run server and agents on a trusted network (a dedicated Docker network as in the examples below is the intended setup), or put a TLS reverse proxy in front of `/v1/certs`.

### Agent mode (fetching certificates from a server)

On any other instance, set `AGENT_MODE=true` and point it at the server. The agent does not need access to `acme.json` at all — it polls the server, writes the certificates to its own `/output` and then runs the exact same post-processing as the normal dumper (`DOMAIN` filtering, `COMBINED_PEM`, `COMBINE_PKCS12`, `CONVERT_KEYS_TO_RSA`, ownership changes, post-hook, container/service restarts):

```yaml
version: '3.7'

services:
  certdumper-agent:
    image: ghcr.io/dimariqe/traefik-cert-sync:latest
    volumes:
      - ./output:/output:rw
    environment:
      AGENT_MODE: "true"
      AGENT_SERVER_ADDRESS: "traefik-cert-sync:3556"   # the server service, see above
      AGENT_KEY: "943faa5f7a1ea76081d4f87ef99ba28966c92e85dd28849384b5ea3473410bf3"
      DOMAIN: "example.com"
```

Put both containers on the same Docker network (`traefik-cert-sync` in the example is the server's service name). Changes to `acme.json` reach the agents within one `AGENT_POLL_INTERVAL` (default: 30 s).

A working multi-node demo is provided in [`dev/docker-compose.agent.yml`](dev/docker-compose.agent.yml).

## Help

If you need help using this image, have suggestions or want to report a problem, feel free to open an issue on GitHub!
