# GitHub Plugin for Falco

This plugin exports several fields that can be used to analyze GitHub activity. The plugin comes with a default set of rules that detect common GitHub-related threats/issues, for example:

- A secret was committed into a repository
- A private repository become public
- A new deploy key was created

The plugin works by installing a webhook on one or more repositories. It then receives and parses the messages from each webhook and, for push messages, the plugin is able to retrieve the files that have been added/changed and parse them.

## Usage

### Prerequisites 
* You will need a github token for your account, which you can get at <https://github.com/settings/tokens>. The token needs, at a minimum, full repo scope, to be able to enumerate the user's repositories and install/remove webhooks. Therefore, in the token creation page, make sure `repo` (and its childs) are checked under `Select scopes`. The token can go in one of these two places:
    * in a file called `github.token` in `~/.ghplugin` (or in the directory pointed by the `SecretsDir` init parameter)
    * in an environment variable called GITHUB_PLUGIN_TOKEN
* The machine where the plugin is running needs a public address and an open firewall that allows either port 80 (for HTTP) or port 443 (for https)

If you want to use https (**highly recommended**), name your key and certificate `server.key` and `server.crt` and put them in `~/.ghplugin` (or in the directory pointed by the `SecretsDir` init parameter). The plugin will pick them up, validate them and start an https server. If the key and certificate are not valid, the plugin will cause falco to exit with an error.

### Initialization parameters

The plugin exports the following init parameters:

- `websocketServerURL`: The URL of the server where the plugin will run, i.e. the plublic accessible address of this machine.
- `secretsDir`: The directory where the secrets required by the plugin are stored. Unless the github token is provided by environment variable, it must be stored in a file named github.token in this directory. In addition, when the webhook server uses HTTPs, server.key and server.crt must be in this directory too. The default value for this parameter is `~/.ghplugin`.
- `useHTTPs`: if this parameter is set to `true`, then the webhook webserver listening at WebsocketServerURL will use HTTPs. In that case, `server.key` and `server.crt` must be present in the SecretsDir directory, or the plugin will fail to load. If the parameter is set to false, the webhook webserver will be plain HTTP. **Use HTTP only for testing or when the plugin is behind a proxy that handles encryption**. The default value for this parameter is `true`.

### Open string format

The plugin's open string is the comma-separated list of repository names that the plugin will monitor.

Finally, specifying `*` as open argument will cause the plugin to instrument all of the available repositories.

### Falco configuration examples

Instrument three specific repositories:
```yaml
  - name: github
    library_path: libgithub.so
    init_config: '{"useHTTPs":true, "websocketServerURL" :"http://foo.ngrok.io"}'
    open_params: 'falcosecurity/falco, falcosecurity/libs, falcosecurity/test-infra'
```

Instrument all of the user's repositores:
```yaml
  - name: github
    library_path: libgithub.so
    init_config: '{"websocketServerURL" :"http://foo.ngrok.io"}'
    open_params: '*'
```

## Webhook lifecycle
The plugin creates a webhook for each of the instrumented repository using the token specified as the first open argument. Each webhook is configured with a unique, automatically generated secret. This allows the plugin to reject messages that don't come from the righful github webhooks.

All of the webhooks are deleted when the plugin event source gets closed (i.e. when Falco reloads or stops).

## Available fields

<!-- README-PLUGIN-FIELDS -->
|                 NAME                  |   TYPE   | ARG  |                                                                                                      DESCRIPTION                                                                                                      |
|---------------------------------------|----------|------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `github.type`                         | `string` | None | Message type, e.g. 'star' or 'repository'.                                                                                                                                                                            |
| `github.action`                       | `string` | None | The github event action. This field typically qualifies the github.type field. For example, a message of type 'star' can have action 'created' or 'deleted'.                                                          |
| `github.user`                         | `string` | None | Name of the user that triggered the event.                                                                                                                                                                            |
| `github.repo`                         | `string` | None | Name of the git repository where the event occurred. Github Webhook payloads contain the repository property when the event occurs from activity in a repository.                                                     |
| `github.org`                          | `string` | None | Name of the organization the git repository belongs to.                                                                                                                                                               |
| `github.owner`                        | `string` | None | Name of the repository's owner.                                                                                                                                                                                       |
| `github.repo.public`                  | `string` | None | 'true' if the repository affected by the action is public. 'false' otherwise.                                                                                                                                         |
| `github.collaborator.name`            | `string` | None | The member name for message that add or remove users.                                                                                                                                                                 |
| `github.collaborator.role`            | `string` | None | The member name for message that add or remove users.                                                                                                                                                                 |
| `github.webhook.id`                   | `string` | None | When a new webhook has been created, the webhook id.                                                                                                                                                                  |
| `github.webhook.type`                 | `string` | None | When a new webhook has been created, the webhook type, e.g. 'repository'.                                                                                                                                             |
| `github.commit.modified`              | `string` | None | Comma separated list of files that have been modified.                                                                                                                                                                |
| `github.diff.has_secrets`             | `string` | None | For push messages, 'true' if the diff of one of the commits contains a secret.                                                                                                                                        |
| `github.diff.committed_secrets.desc`  | `string` | None | For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the description of each of the committed secrets, as a comma separated list.                  |
| `github.diff.committed_secrets.files` | `string` | None | For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the names of the files in which each of the secrets was committed, as a comma separated list. |
| `github.diff.committed_secrets.lines` | `string` | None | For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the file line positions of the committed secrets, as a comma separated list.                  |
| `github.diff.committed_secrets.links` | `string` | None | For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the github source code link for each of the committed secrets, as a comma separated list.     |
| `github.workflow.has_miners`          | `string` | None | For workflow_run messages, 'true' if the a miner has been detected in the workflow definition file.                                                                                                                   |
| `github.workflow.miners.type`         | `string` | None | For workflow_run messages, if one or more miners is detected in the workflow definition file, this field contains the type of each of the detected miner, as a comma separated list (e.g. xmrig, stratum).            |
| `github.workflow.filename`            | `string` | None | For workflow_run messages, the name of the workflow definition file.                                                                                                                                                  |
<!-- /README-PLUGIN-FIELDS -->

## Types of detected secrets

The plugin can currently detect when the following types of secrets are committed into one of the repos:

- aws_access_key
- aws_secret_key
- aws_mws_key
- facebook_secret_key
- facebook_client_id
- twitter_secret_key
- twitter_client_id
- github_personal_access_token
- github_oauth_access_token
- github_app_token
- github_refresh_token
- linkedin_client_id
- linkedin_secret_key
- slack
- asymmetric_private_key
- google_api_key
- google_gcp_service_account
- heroku_api_key
- mailchimp_api_key
- mailgun_api_key
- paypal_braintree_access_token
- picatic_api_key
- sendgrid_api_key
- slack_webhook
- stripe_api_key
- square_access_token
- square_oauth_secret
- twilio_api_key
- dynatrace_token
- shopify_shared_secret
- shopify_access_token
- shopify_custom_app_access_token
- shopify_private_app_access_token
- pypi_upload_token

Adding a new secret detection is simply a matter of adding a new entry in the secretsChecks array in [secrets.go](https://github.com/falcosecurity/plugins/blob/master/plugins/github/pkg/github/secrets.go).
