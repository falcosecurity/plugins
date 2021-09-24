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

| Name | Type | Description |
| ---- | ---- | ----------- |
| ct.id | string | the unique ID of the cloudtrail event (eventID in the json).
| ct.time | string | the timestamp of the cloudtrail event (eventTime in the json).
| ct.src | string | the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer).
| ct.name | string | the name of the cloudtrail event (eventName in the json).
| ct.user | string | the user of the cloudtrail event (userIdentity.userName in the json).
| ct.region | string | the region of the cloudtrail event (awsRegion in the json).
| ct.srcip | string | the IP address generating the event (sourceIPAddress in the json).
| ct.useragent | string | the user agent generating the event (userAgent in the json).
| ct.info | string | summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details.
| ct.readonly | string | 'true' if the event only reads information (e.g. DescribeInstances), 'false' if the event modifies the state (e.g. RunInstances, CreateLoadBalancer...).
| s3.uri | string | the s3 URI (s3://<bucket>/<key>).
| s3.buckey | string | the bucket name for s3 events.
| s3.key | string | the S3 key name.
| s3.host | string |  the S3 host name.
| s3.bytes | string | the size of an s3 download or upload, in bytes.
| s3.bytes.in | string | the size of an s3 upload, in bytes.
| s3.bytes.out | string | the size of an s3 download, in bytes.
| s3.cnt.get | string | the number of get operations. This field is 1 for GetObject events, 0 otherwise.
| s3.cnt.put | string | the number of put operations. This field is 1 for PutObject events, 0 otherwise.
| s3.cnt.other | string | the number of non I/O operations. This field is 0 for GetObject and PutObject events, 1 for all the other events.
| ec2.name | string | the name of the ec2 instances, typically stored in the instance tags.

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
{"sqsDelete": false, "s3DownloadConcurrency": 64}
```

The json object has the following properties:

* `sqsDelete`: value is boolean. If true, then the plugin will delete sqs messages from the queue immediately after receiving them. (Default: true)
* `s3DownloadConcurrency`: value is numeric. Controls the number of background goroutines used to download S3 files. (Default: 1)

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
load_plugins: [cloudtrail]
```

```yaml
# Cloudtrail reading from a SQS Queue
plugins:
  - name: cloudtrail
    library_path: libcloudtrail.so
    init_config: '{"sqsDelete": true}'
    open_params: "sqs://my-sqs-queue"

# Optional. If not specified the first entry in plugins is used.
load_plugins: [cloudtrail]
```

```yaml
# Cloudtrail reading from a single file
plugins:
  - name: cloudtrail
    library_path: libcloudtrail.so
    init_config: ""
    open_params: "/home/user/cloudtrail-logs/059797578166_CloudTrail_us-east-1_20210209T0130Z_65lDDH3uferZH5Br.json.gz"

# Optional. If not specified the first entry in plugins is used.
load_plugins: [cloudtrail]
```

### Using SNS/SQS to Route Cloudtrail Events to the Plugin

Note that the plugin does not create any Cloudtrails, S3 Buckets, SNS Notifications, or SQS Queues. It assumes that those resources have already been created.

The general steps involve:

1. Creating a Cloudtrail with the events you would like to monitor: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
2. Configuring SNS Notifications for Cloudtrail: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html
3. Creating a SQS Queue to receive the SNS Notifications: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-subscribe-queue-sns-topic.html
