# Falcosecurity RDS Plugin

This directory contains the [AWS Aurora](https://aws.amazon.com/rds/aurora/?aurora-whats-new.sort-by=item.additionalFields.postDateTime&aurora-whats-new.sort-order=desc) plugin, which can fetch logs exported on  containing database events, parse the log files, and emit sinsp/scap events (e.g. the events used by Falco) for each log entry.

The plugin can be configured to obtain log files from RDS Aurora (MySQL/PostgreSQL)

The plugin also extract information from the logged SQL queries such as type of command and various arguments.

## Event Source

The event source for cloudtrail events is `aws_aurora`.

## Supported Fields

Here is the current set of supported fields:

| Name                | Type | Description |
|---------------------| ---- | ----------- |
| aurora.timestamp    | string | Timestamp with millisec precision. 
| aurora.serverhost   | string | The name of the instance that the event is logged for.
| aurora.username     | string | The connected user name of the user.
| aurora.host         | string | The host that the user connected from.
| aurora.connectionid | string | The connection ID number for the logged operation.
| aurora.queryid      | string | The query ID number, which can be used for finding the relational table events and related queries. For TABLE events, multiple lines are added.
| aurora.operation    | string | The recorded action type. Possible values are: CONNECT, QUERY, READ, WRITE, CREATE, ALTER, RENAME, and DROP. QUERY actions are further processed by the plugin.
| aurora.database     | string | The active database, as set by the USE command.
| aurora.object       | string | For QUERY events, this value indicates the query that the database performed. For TABLE events, it indicates the table name.
| aurora.retcode      | string | The return code of the logged operation.
| aurora.stream       | string | Cloudwatch stream id used to fetch this log.
| aurora.isselect     | string | True if a QUERY operation contains SELECT statements.
| aurora.isset        | string | True if a QUERY operation contains SET statements.
| aurora.iscreate     | string | True if a QUERY operation contains CREATE statements.
| aurora.isdrop       | string | True if a QUERY operation contains SELECT statements.
| aurora.isupdate     | string | True if a QUERY operation contains UPDATE statements.
| aurora.isinsert     | string | True if a QUERY operation contains INSERT statements.
| aurora.isgrant      | string | True if a QUERY operation contains GRANT statements.
| aurora.isrevoke     | string | True if a QUERY operation contains REVOKE statements.
| aurora.isalter      | string | True if a QUERY operation contains ALTER statements.
| aurora.isdelete     | string | True if a QUERY operation contains DELETE statements.
| aurora.dropargs     | string | DROP statemtent arguments, if present.
| aurora.selectargs   | string | SELECT statemtent arguments, if present.
| aurora.setargs      | string | SET statemtent arguments, if present.
| aurora.where        | strign | WHERE clause, if present.
| aurora.createloc    | string | CREATE statement location, if present.
| aurora.createargs   | string | CREATE statement elements, if present.
| aurora.updateargs   | string | UPDATE statement arguments, if present.
| aurora.insertclmns  | string | INSERT statement columns argument, if present.
| aurora.inserttable  | string | INSERT statement table argument, if present.
| aurora.grantargs    | string | GRANT statement roles/privileges, if present.
| aurora.grantusr     | string | GRANT statement users, if present.
| aurora.revokeargs   | string | REVOKE statement roles/privileges, if present.
| aurora.altertable | string | ALTER statement table, if present.
| aurora.deletable | string | DELETE table arguments, if present.

## Handling AWS Authentication

When reading log files exported on Cloudwatch, the plugin needs authentication credentials and to be configured with an AWS Region. The plugin relies on the same authentication mechanisms used by the [AWS Go SDK](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#specifying-credentials):

* Environment Variables: specify the aws region with `AWS_REGION=xxx`, the access key id with `AWS_ACCESS_KEY_ID=xxx`, and the secret key with `AWS_SECRET_ACCESS_KEY=xxx`. Here's a sample command line:

* Shared Configuration Files: specify the aws region in a file at `$HOME/.aws/config` and the credentials in a file at `$HOME/.aws/credentials`. Here are example files:

#### **`$HOME/.aws/config`**
```shell
[default]
region = us-west-1
```

#### **`$HOME/.aws/credentials`**
```shell
[default]
aws_access_key_id=<YOUR-AWS-ACCESS-KEY-ID-HERE>
aws_secret_access_key=<YOUR-AWS-SECRET-ACCESS-KEY-HERE>
```
## Configuration
The plugins needs an Aurora instance to have auditing enabled following [these steps](https://aws.amazon.com/blogs/database/auditing-an-amazon-aurora-cluster/), and its logs [exported on Cloudwatch](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Integrating.CloudWatch.html).

Plugins loading and its Open Params can be configured following [these steps](https://falco.org/docs/plugins/#how-falco-uses-plugins)

### Plugin Open Params

The format of the open params string is the name of the Aurora cluster which is going to be monitored:

* `    open_params: "mycluster"`

## TODO 
* Monitor past logs/events
* Generalize this plugin for MySQL and PostgreSQL (RDS non-Aurora)