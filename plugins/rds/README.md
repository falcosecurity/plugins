# Falcosecurity RDS Plugin

This directory contains the [AWS RDS](https://aws.amazon.com/rds/) plugin, which can fetch logs exported on Cloudwatch containing database events, parse the log files, and emit sinsp/scap events (e.g. the events used by Falco) for each log entry.

The plugin is compatible with RDS Aurora (MySQL/PostgreSQL), RDS MySQL and RDS MariaDB

The plugin also extract information from the logged SQL queries such as type of command and various arguments.

## Event Source

The event source for cloudtrail events is `aws_rds`

## Supported Fields

Here is the current set of supported fields:

| Name             | Type | Description |
|------------------| ---- | ----------- |
| rds.timestamp    | string | Timestamp with millisec precision. 
| rds.serverhost   | string | The name of the instance that the event is logged for.
| rds.username     | string | The connected user name of the user.
| rds.host         | string | The host that the user connected from.
| rds.connectionid | string | The connection ID number for the logged operation.
| rds.queryid      | string | The query ID number, which can be used for finding the relational table events and related queries. For TABLE events, multiple lines are added.
| rds.operation    | string | The recorded action type. Possible values are: CONNECT, QUERY, READ, WRITE, CREATE, ALTER, RENAME, and DROP. QUERY actions are further processed by the plugin.
| rds.database     | string | The active database, as set by the USE command.
| rds.object       | string | For QUERY events, this value indicates the query that the database performed. For TABLE events, it indicates the table name.
| rds.retcode      | string | The return code of the logged operation.
| rds.stream       | string | Cloudwatch stream id used to fetch this log.
| rds.isselect     | string | True if a QUERY operation contains SELECT statements.
| rds.isset        | string | True if a QUERY operation contains SET statements.
| rds.iscreate     | string | True if a QUERY operation contains CREATE statements.
| rds.isdrop       | string | True if a QUERY operation contains SELECT statements.
| rds.isupdate     | string | True if a QUERY operation contains UPDATE statements.
| rds.isinsert     | string | True if a QUERY operation contains INSERT statements.
| rds.isgrant      | string | True if a QUERY operation contains GRANT statements.
| rds.isrevoke     | string | True if a QUERY operation contains REVOKE statements.
| rds.isalter      | string | True if a QUERY operation contains ALTER statements.
| rds.isdelete     | string | True if a QUERY operation contains DELETE statements.
| rds.dropargs     | string | DROP statemtent arguments, if present.
| rds.selectargs   | string | SELECT statemtent arguments, if present.
| rds.setargs      | string | SET statemtent arguments, if present.
| rds.where        | strign | WHERE clause, if present.
| rds.createloc    | string | CREATE statement location, if present.
| rds.createargs   | string | CREATE statement elements, if present.
| rds.updateargs   | string | UPDATE statement arguments, if present.
| rds.insertclmns  | string | INSERT statement columns argument, if present.
| rds.inserttable  | string | INSERT statement table argument, if present.
| rds.grantargs    | string | GRANT statement roles/privileges, if present.
| rds.grantusr     | string | GRANT statement users, if present.
| rds.revokeargs   | string | REVOKE statement roles/privileges, if present.
| rds.altertable   | string | ALTER statement table, if present.
| rds.deletable    | string | DELETE table arguments, if present.

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
If listening to an RDS Aurora instance, RDS MySQL or RDS MariaDB, these needs to have auditing enabled and logs exported on Cloudwatch:
* RDS Aurora following [these steps](https://aws.amazon.com/blogs/database/auditing-an-amazon-aurora-cluster/), and its logs [exported on Cloudwatch](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Integrating.CloudWatch.html).
* RDS MySQL or RDS MariaDB following [these steps](https://aws.amazon.com/premiumsupport/knowledge-center/advanced-audit-rds-mysql-cloudwatch/)

Plugins loading and its Open Params can be configured following [these steps](https://falco.org/docs/plugins/#how-falco-uses-plugins)

### Plugin Open Params

The format of the open params string is the name of the Aurora cluster which is going to be monitored:

* `    open_params: "mycluster"`

## TODO 
* Monitor past logs/events