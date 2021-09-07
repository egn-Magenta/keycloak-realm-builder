# Keycloak Realm Builder

TODO documentation...

## Development Tip

The following development workflow can be used in order to save some time starting and stopping the
Keycloak stack.

1. Build the realm builder image with `docker build -t magentaaps/os2mo-keycloak-realm-builder:dev .`
2. Create a Docker ENV file, e.g. `test.env` containing the relevant
   ENVs - for example
   ```
   KEYCLOAK_LORA_REALM_ENABLED=true
   KEYCLOAK_LORA_CLIENT_SECRET=158a2075-aa8a-421c-94a4-2df35377014a
   ```
3. Inspect the realm builder output by running
   ```
   $ docker run --rm --env-file=test.env magentaaps/os2mo-keycloak-realm-builder:dev \
     python main.py --dry-run
   ```

For convenience, the output cann be piped to `jq` (installed with e.g.
`sudo apt install jq`) for a nicer output, e.g.
```
$ docker run --rm --env-file=test.env magentaaps/os2mo-keycloak-realm-builder:dev \
  python main.py --dry-run | jq
```
for everything or
```
$ docker run --rm --env-file=test.env magentaaps/os2mo-keycloak-realm-builder:dev \
  python main.py --dry-run | jq .[0].realm
```
to see the name of the first realm in the output JSON list.