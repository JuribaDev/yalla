# Promotion

Promotion moves a known source and build configuration from one environment to
another without mutating the source environment.

## Flow

1. Read `.yalla.yaml` and fetch source and target services with
   `yalla service get`.
2. Confirm the target environment and service.
3. Mirror the source build configuration into the target service.
4. Apply target-specific environment values through public Yalla commands when
   available.
5. Deploy the target service and verify it.

## Commands

```sh
yalla service get --service-id svc_app_staging --json
yalla service build set --service-id svc_app_prod --build-type image --image ghcr.io/acme/app:v1.2.3 --port 3000 --json
yalla service deploy --service-id svc_app_prod --wait --json
```

Never deploy the source service as part of promotion unless the user explicitly
asks for that separate action.
