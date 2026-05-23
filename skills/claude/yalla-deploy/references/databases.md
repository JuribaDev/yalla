# Databases

Use Yalla database commands for provisioned database services and backup
operations. Keep generated passwords and connection strings out of tracked
files.

## Create a database service

```sh
yalla database create --environment-id env_app_prod --service-id svc_app_db --name app-db --engine postgres --deploy --json
```

The current CLI creates the database service record and queues provisioning
through the backend. It does not accept raw database passwords on the command
line. If the app points at an externally managed database, do not create a
Yalla database service; pass the existing connection value through the service
environment configuration.

## Backup schedule and manual run

```sh
yalla database backup create --service-id svc_app_db --backup-id sbkp_daily --name daily --schedule "0 2 * * *" --json
yalla database backup run --service-id svc_app_db --backup-id sbkp_daily --wait --json
```

## Restore

```sh
yalla database backup restore --service-id svc_app_db --backup-id sbkp_daily --wait --json
```

Before restore, confirm the target service, data-loss risk, and whether the user
needs a fresh backup first.
