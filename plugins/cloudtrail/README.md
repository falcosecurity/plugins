# Falcosecurity Cloudtrail Plugin

This directory contains the cloudtrail plugin, which can fetch log files containing [cloudtrail](https://aws.amazon.com/cloudtrail/) events, parse the log files, and emit sinsp/scap events (e.g. the events used by Falco) for each cloudtrail log entry.

The plugin can be configured to obtain log files from:

* A S3 bucket
* A SQS queue that passes along SNS notifications about new log files
* A local filesystem path

The plugin also exports fields that extract information from a cloudtrail event, such as the event time, the aws region, S3 bucket/EC2 instance names, etc.

## Event Source

The event source for cloudtrail events is `aws_cloudtrail`.

## Supported Fields

Here is the current set of supported fields:

<!-- README-PLUGIN-FIELDS -->
|             NAME             |   TYPE   | ARG  | DESCRIPTION                                                                                                                                              |
|------------------------------|----------|------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ct.id`                      | `string` | None | the unique ID of the cloudtrail event (eventID in the json).                                                                                             |
| `ct.error`                   | `string` | None | The error code from the event. Will be "<NA>" (e.g. the NULL/empty/none value) if there was no error.                                                    |
| `ct.time`                    | `string` | None | the timestamp of the cloudtrail event (eventTime in the json).                                                                                           |
| `ct.src`                     | `string` | None | the source of the cloudtrail event (eventSource in the json).                                                                                            |
| `ct.shortsrc`                | `string` | None | the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer).                                                      |
| `ct.name`                    | `string` | None | the name of the cloudtrail event (eventName in the json).                                                                                                |
| `ct.user`                    | `string` | None | the user of the cloudtrail event (userIdentity.userName in the json).                                                                                    |
| `ct.user.accountid`          | `string` | None | the account id of the user of the cloudtrail event.                                                                                                      |
| `ct.user.identitytype`       | `string` | None | the kind of user identity (e.g. Root, IAMUser,AWSService, etc.)                                                                                          |
| `ct.user.principalid`        | `string` | None | A unique identifier for the user that made the request.                                                                                                  |
| `ct.user.arn`                | `string` | None | the Amazon Resource Name (ARN) of the user that made the request.                                                                                        |
| `ct.region`                  | `string` | None | the region of the cloudtrail event (awsRegion in the json).                                                                                              |
| `ct.response.subnetid`       | `string` | None | the subnet ID included in the response.                                                                                                                  |
| `ct.response.reservationid`  | `string` | None | the reservation ID included in the response.                                                                                                             |
| `ct.request.availabilityzone` | `string` | None | the availability zone included in the request.                                                                                                           |
| `ct.request.cluster`         | `string` | None | the cluster included in the request.                                                                                                                     |
| `ct.request.functionname`    | `string` | None | the function name included in the request.                                                                                                               |
| `ct.request.groupname`       | `string` | None | the group name included in the request.                                                                                                                  |
| `ct.request.host`            | `string` | None | the host included in the request                                                                                                                         |
| `ct.request.name`            | `string` | None | the name of the entity being acted on in the request.                                                                                                    |
| `ct.request.policy`          | `string` | None | the policy included in the request                                                                                                                       |
| `ct.request.serialnumber`    | `string` | None | the serial number provided in the request.                                                                                                               |
| `ct.request.servicename`     | `string` | None | the service name provided in the request.                                                                                                                |
| `ct.request.subnetid`        | `string` | None | the subnet ID provided in the request.                                                                                                                   |
| `ct.request.taskdefinition`  | `string` | None | the task definition prrovided in the request.                                                                                                            |
| `ct.request.username`        | `string` | None | the username provided in the request.                                                                                                                    |
| `ct.srcip`                   | `string` | None | the IP address generating the event (sourceIPAddress in the json).                                                                                       |
| `ct.useragent`               | `string` | None | the user agent generating the event (userAgent in the json).                                                                                             |
| `ct.info`                    | `string` | None | summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details.                   |
| `ct.managementevent`         | `string` | None | 'true' if the event is a management event (AwsApiCall, AwsConsoleAction, AwsConsoleSignIn, or AwsServiceEvent), 'false' otherwise.                       |
| `ct.readonly`                | `string` | None | 'true' if the event only reads information (e.g. DescribeInstances), 'false' if the event modifies the state (e.g. RunInstances, CreateLoadBalancer...). |
| `s3.uri`                     | `string` | None | the s3 URI (s3://<bucket>/<key>).                                                                                                                        |
| `s3.bucket`                  | `string` | None | the bucket name for s3 events.                                                                                                                           |
| `s3.key`                     | `string` | None | the S3 key name.                                                                                                                                         |
| `s3.bytes`                   | `uint64` | None | the size of an s3 download or upload, in bytes.                                                                                                          |
| `s3.bytes.in`                | `uint64` | None | the size of an s3 upload, in bytes.                                                                                                                      |
| `s3.bytes.out`               | `uint64` | None | the size of an s3 download, in bytes.                                                                                                                    |
| `s3.cnt.get`                 | `uint64` | None | the number of get operations. This field is 1 for GetObject events, 0 otherwise.                                                                         |
| `s3.cnt.put`                 | `uint64` | None | the number of put operations. This field is 1 for PutObject events, 0 otherwise.                                                                         |
| `s3.cnt.other`               | `uint64` | None | the number of non I/O operations. This field is 0 for GetObject and PutObject events, 1 for all the other events.                                        |
| `ec2.name`                   | `string` | None | the name of the ec2 instances, typically stored in the instance tags.                                                                                    |
| `ec2.imageid`                | `string` | None | the ID for the image used to run the ec2 instance in the response.                                                                                       |
| `ecr.repository`             | `string` | None | the name of the ecr Repository specified in the request.                                                                                                 |
| `ecr.imagetag`               | `string` | None | the tag of the image specified in the request.                                                                                                           |
<!-- /README-PLUGIN-FIELDS -->

## Handling AWS Authentication

When reading log files from a S3 bucket or when reading SNS notifications from a SQS queue, the plugin needs authentication credentials and to be configured with an AWS Region. The plugin relies on the same authentication mechanisms used by the [AWS Go SDK](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#specifying-credentials):

* Environment Variables: specify the aws region with `AWS_REGION=xxx`, the access key id with `AWS_ACCESS_KEY_ID=xxx`, and the secret key with `AWS_SECRET_ACCESS_KEY=xxx`. Here's a sample command line:

```shell
AWS_DEFAULT_REGION=us-west-1 AWS_ACCESS_KEY_ID=XXX AWS_SECRET_ACCESS_KEY=XXX falco -c <path-to-falco.yaml> -r <path-to-falco-rules>
```

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

### Plugin Initialization

The format of the initialization string is a json object. Here's an example:

```json
{"sqsDelete": false, "s3DownloadConcurrency": 64, "useS3SNS": true}
```

The json object has the following properties:

* `sqsDelete`: value is boolean. If true, then the plugin will delete sqs messages from the queue immediately after receiving them. (Default: true)
* `s3DownloadConcurrency`: value is numeric. Controls the number of background goroutines used to download S3 files. (Default: 1)
* `useS3SNS`: value is boolean. If true, then the plugin will expect SNS messages to originate from S3 instead of directly from Cloudtrail (Default: false)

The init string can be the empty string, which is treated identically to `{}`.

### Plugin Open Params

The format of the open params string is a uri-like string with one of the following forms:

* `s3://<S3 Bucket Name>[/<Optional Prefix>]`
* `sqs://<SQS Queue Name>`
* `<Some Filesystem Path>`

We describe each of these below.

#### Read From S3 Bucket Directly

When using `s3://<S3 Bucket Name>/[<Optional Prefix>]`, the plugin will scan the bucket a single time for all objects. Characters up to the first slash/end of string will be used as the S3 bucket name, and any remaining characters will be treated as a key prefix. After reading all objects, the plugin will return EOF.

All objects below the bucket, or below the bucket + prefix, will be considered cloudtrail logs. Any object ending in .json.gz will be decompressed first.

For example, if a bucket `my-s3-bucket` contained cloudtrail logs below a prefix `AWSLogs/411571310278/CloudTrail/us-west-1/2021/09/23/`, Using an open params of `s3://my-s3-bucket/AWSLogs/411571310278/CloudTrail/us-west-1/2021/09/23/` would configure the plugin to read all files below `AWSLogs/411571310278/CloudTrail/us-west-1/2021/09/23/` as cloudtrail logs and then return EOF. No other files in the bucket will be read.

#### Read from SQS Queue

When using `sqs://<SQS Queue Name>`, the plugin will read messages from the provided SQS Queue. The messages are assumed to be [SNS Notifications](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html) that announce the presence of new Cloudtrail log files in a S3 bucket. Each new file will be read from the provided s3 bucket.

In this mode, the plugin polls the queue forever, waiting for new log files.

#### Read single file

All other open params are interpreted as a filesystem path to a single cloudtrail log file. This fill will be read and parsed. When complete, the plugin returns EOF.

### `falco.yaml` Example

Here is a complete `falco.yaml` snippet showing valid configurations for the cloudtrail plugin:

```yaml
# Cloudtrail reading from a S3 Bucket
plugins:
  - name: cloudtrail
    library_path: libcloudtrail.so
    init_config: ""
    open_params: "s3://my-s3-bucket/AWSLogs/411571310278/CloudTrail/us-west-1/2021/09/23/"

# Optional. If not specified the first entry in plugins is used.
load_plugins: [cloudtrail, json]
```

```yaml
# Cloudtrail reading from a SQS Queue
plugins:
  - name: cloudtrail
    library_path: libcloudtrail.so
    init_config: '{"sqsDelete": true}'
    open_params: "sqs://my-sqs-queue"

# Optional. If not specified the first entry in plugins is used.
load_plugins: [cloudtrail, json]
```

```yaml
# Cloudtrail reading from a single file
plugins:
  - name: cloudtrail
    library_path: libcloudtrail.so
    init_config: ""
    open_params: "/home/user/cloudtrail-logs/059797578166_CloudTrail_us-east-1_20210209T0130Z_65lDDH3uferZH5Br.json.gz"

# Optional. If not specified the first entry in plugins is used.
load_plugins: [cloudtrail, json]
```

### Using SNS/SQS to Route Cloudtrail Events to the Plugin

Note that the plugin does not create any Cloudtrails, S3 Buckets, SNS Notifications, or SQS Queues. It assumes that those resources have already been created.

The general steps involve:

1. Creating a Cloudtrail with the events you would like to monitor: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
2. Configuring SNS Notifications for Cloudtrail: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html
3. Creating a SQS Queue to receive the SNS Notifications: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-subscribe-queue-sns-topic.html
