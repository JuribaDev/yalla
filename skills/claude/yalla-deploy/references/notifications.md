# Notifications

Notification requests must identify event types, target channel, and secret
handling for webhooks or credentials.

If no first-class Yalla command exists for this workflow in `yalla --json
manifest`, do not invent a private API operation. State the missing Yalla
command, stop before mutation, and ask the user whether they want a follow-up
implementation task.

Webhook URLs and credentials are secrets. Do not echo them back in full and do
not write them to tracked files.
