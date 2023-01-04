/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"
	"github.com/valyala/fastjson"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

type OpenMode int

const (
	fileMode OpenMode = iota
	s3Mode
	sqsMode
)

type fileInfo struct {
	name         string
	isCompressed bool
}

// This is the state that we use when reading events from an S3 bucket
type s3State struct {
	bucket                string
	client                *s3.Client
	downloader            *manager.Downloader
	DownloadWg            sync.WaitGroup
	DownloadBufs          [][]byte
	lastDownloadedFileNum int
	nFilledBufs           int
	curBuf                int
}

type snsMessage struct {
	Bucket string   `json:"s3Bucket"`
	Keys   []string `json:"s3ObjectKey"`
}

// This is the open state, identifying an open instance reading cloudtrail files from
// a local directory or from a remote S3 bucket (either direct or via a SQS queue)
type PluginInstance struct {
	source.BaseInstance
	openMode           OpenMode
	awsConfig          aws.Config
	config             PluginConfig
	cloudTrailFilesDir string
	files              []fileInfo
	curFileNum         uint32
	evtJSONStrings     [][]byte
	evtJSONListPos     int
	s3                 s3State
	sqsClient          *sqs.Client
	queueURL           string
	nextJParser        fastjson.Parser
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (oCtx *PluginInstance) openLocal(params string) error {
	oCtx.openMode = fileMode

	oCtx.cloudTrailFilesDir = params

	if len(oCtx.cloudTrailFilesDir) == 0 {
		return fmt.Errorf(PluginName + " plugin error: missing input directory argument")
	}

	if !dirExists(oCtx.cloudTrailFilesDir) {
		return fmt.Errorf(PluginName+" plugin error: cannot open %s", oCtx.cloudTrailFilesDir)
	}

	err := filepath.Walk(oCtx.cloudTrailFilesDir, func(path string, info os.FileInfo, err error) error {
		if info != nil && info.IsDir() {
			return nil
		}

		isCompressed := strings.HasSuffix(path, ".json.gz")
		if filepath.Ext(path) != ".json" && !isCompressed {
			return nil
		}

		var fi fileInfo = fileInfo{name: path, isCompressed: isCompressed}
		oCtx.files = append(oCtx.files, fi)
		return nil
	})
	if err != nil {
		return err
	}
	if len(oCtx.files) == 0 {
		return fmt.Errorf(PluginName + " plugin error: no json files found in " + oCtx.cloudTrailFilesDir)
	}

	return nil
}

func (p *PluginInstance) initS3() error {
	if p.s3.client == nil {
		// Create an array of download buffers that will be used to concurrently
		// download files from s3
		p.s3.DownloadBufs = make([][]byte, p.config.S3DownloadConcurrency)
		p.s3.client = s3.NewFromConfig(p.awsConfig)
		p.s3.downloader = manager.NewDownloader(p.s3.client)
	}
	return nil
}

func (oCtx *PluginInstance) openS3(input string) error {
	oCtx.openMode = s3Mode

	// remove the initial "s3://"
	input = input[5:]
	slashindex := strings.Index(input, "/")

	// Extract the URL components
	var prefix string
	if slashindex == -1 {
		oCtx.s3.bucket = input
		prefix = ""
	} else {
		oCtx.s3.bucket = input[:slashindex]
		prefix = input[slashindex+1:]
	}

	if err := oCtx.initS3(); err != nil {
		return err
	}

	// Fetch the list of keys
	ctx := context.Background()
	paginator := s3.NewListObjectsV2Paginator(oCtx.s3.client, &s3.ListObjectsV2Input{
		Bucket: &oCtx.s3.bucket,
		Prefix: &prefix,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// Try friendlier error sources first.
			var aErr smithy.APIError
			if errors.As(err, &aErr) {
				return fmt.Errorf(PluginName + " plugin error: %s: %s", aErr.ErrorCode(), aErr.ErrorMessage())
			}

			var oErr *smithy.OperationError
			if errors.As(err, &oErr) {
				return fmt.Errorf(PluginName + " plugin error: %s: %s", oErr.Service(), oErr.Unwrap())
			}

			return fmt.Errorf(PluginName + " plugin error: failed to list objects: " + err.Error())
		}
		for _, obj := range page.Contents {
			path := obj.Key
			isCompressed := strings.HasSuffix(*path, ".json.gz")
			if filepath.Ext(*path) != ".json" && !isCompressed {
				continue
			}

			var fi fileInfo = fileInfo{name: *path, isCompressed: isCompressed}
			oCtx.files = append(oCtx.files, fi)
		}
	}

	return nil
}

func (oCtx *PluginInstance) getMoreSQSFiles() error {
	ctx := context.Background()

	input := &sqs.ReceiveMessageInput{
		MessageAttributeNames: []string{
			string(types.QueueAttributeNameAll),
		},
		QueueUrl:            &oCtx.queueURL,
		MaxNumberOfMessages: 1,
	}

	msgResult, err := oCtx.sqsClient.ReceiveMessage(ctx, input)

	if err != nil {
		return err
	}

	if len(msgResult.Messages) == 0 {
		return nil
	}

	if oCtx.config.SQSDelete {
		// Delete the message from the queue so it won't be read again
		delInput := &sqs.DeleteMessageInput{
			QueueUrl:      &oCtx.queueURL,
			ReceiptHandle: msgResult.Messages[0].ReceiptHandle,
		}

		_, err = oCtx.sqsClient.DeleteMessage(ctx, delInput)

		if err != nil {
			return err
		}
	}

	// The SQS message is just a SNS notification noting that new
	// cloudtrail file(s) are available in the s3 bucket. Download
	// those files.

	var sqsMsg map[string]interface{}

	err = json.Unmarshal([]byte(*msgResult.Messages[0].Body), &sqsMsg)

	if err != nil {
		return err
	}

	messageType, ok := sqsMsg["Type"]
	if !ok {
		return fmt.Errorf("received SQS message that did not have a Type property")
	}

	if messageType.(string) != "Notification" {
		return fmt.Errorf("received SQS message that was not a SNS Notification")
	}

	if oCtx.config.UseS3SNS {
		// Process SNS message coming from S3
		var (
			s3Event    events.S3Event
			s3Init     bool
			lastBucket string
		)

		err = json.Unmarshal([]byte(sqsMsg["Message"].(string)), &s3Event)

		if err != nil {
			return err
		}

		for _, record := range s3Event.Records {

			// init s3 and set bucket changes
			if !s3Init || record.S3.Bucket.Name != lastBucket {
				oCtx.s3.bucket = record.S3.Bucket.Name

				// only init s3 once
				if !s3Init {
					if err := oCtx.initS3(); err != nil {
						return err
					}
					s3Init = true
				}
			}

			isCompressed := strings.HasSuffix(record.S3.Object.Key, ".json.gz")

			oCtx.files = append(oCtx.files, fileInfo{name: record.S3.Object.Key, isCompressed: isCompressed})

			lastBucket = record.S3.Bucket.Name
		}

		return nil
	}

	var notification snsMessage

	err = json.Unmarshal([]byte(sqsMsg["Message"].(string)), &notification)

	if err != nil {
		return err
	}

	// The notification contains a bucket and a list of keys that
	// contain new cloudtrail files.
	oCtx.s3.bucket = notification.Bucket

	if err := oCtx.initS3(); err != nil {
		return err
	}

	for _, key := range notification.Keys {

		isCompressed := strings.HasSuffix(key, ".json.gz")

		oCtx.files = append(oCtx.files, fileInfo{name: key, isCompressed: isCompressed})
	}

	return nil
}

func (oCtx *PluginInstance) openSQS(input string) error {
	ctx := context.Background()

	oCtx.openMode = sqsMode

	oCtx.sqsClient = sqs.NewFromConfig(oCtx.awsConfig)

	queueName := input[6:]

	urlResult, err := oCtx.sqsClient.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: &queueName})

	if err != nil {
		return err
	}

	oCtx.queueURL = *urlResult.QueueUrl

	return oCtx.getMoreSQSFiles()
}

var dlErrChan chan error

func (oCtx *PluginInstance) s3Download(downloader *manager.Downloader, name string, dloadSlotNum int) {
	defer oCtx.s3.DownloadWg.Done()

	ctx := context.Background()
	buff := manager.NewWriteAtBuffer(nil)
	_, err := downloader.Download(ctx, buff,
		&s3.GetObjectInput{
			Bucket: &oCtx.s3.bucket,
			Key:    &name,
		})
	if err != nil {
		dlErrChan <- err
		return
	}

	oCtx.s3.DownloadBufs[dloadSlotNum] = buff.Bytes()
}

func (oCtx *PluginInstance) readNextFileS3() ([]byte, error) {
	if oCtx.s3.curBuf < oCtx.s3.nFilledBufs {
		curBuf := oCtx.s3.curBuf
		oCtx.s3.curBuf++
		return oCtx.s3.DownloadBufs[curBuf], nil
	}

	dlErrChan = make(chan error, oCtx.config.S3DownloadConcurrency)
	k := oCtx.s3.lastDownloadedFileNum
	oCtx.s3.nFilledBufs = min(oCtx.config.S3DownloadConcurrency, len(oCtx.files)-k)
	for j, f := range oCtx.files[k : k+oCtx.s3.nFilledBufs] {
		oCtx.s3.DownloadWg.Add(1)
		go oCtx.s3Download(oCtx.s3.downloader, f.name, j)
	}
	oCtx.s3.DownloadWg.Wait()

	select {
	case e := <-dlErrChan:
		return nil, e
	default:
	}

	oCtx.s3.lastDownloadedFileNum += oCtx.s3.nFilledBufs

	oCtx.s3.curBuf = 1
	return oCtx.s3.DownloadBufs[0], nil
}

func readFileLocal(fileName string) ([]byte, error) {
	return ioutil.ReadFile(fileName)
}

func extractRecordStrings(jsonStr []byte, res *[][]byte) {
	indentation := 0
	var entryStart int

	for pos, char := range jsonStr {
		if char == '{' {
			if indentation == 1 {
				entryStart = pos
			}
			indentation++
		} else if char == '}' {
			indentation--
			if indentation == 1 {
				if pos < len(jsonStr)-1 {
					entry := jsonStr[entryStart : pos+1]
					*res = append(*res, entry)
				}
			}
		}
	}
}

// nextEvent is the core event production function.
func (oCtx *PluginInstance) nextEvent(evt sdk.EventWriter) error {
	var evtData []byte
	var tmpStr []byte
	var err error

	// Only open the next file once we're sure that the content of the previous one has been full consumed
	if oCtx.evtJSONListPos >= len(oCtx.evtJSONStrings) {
		// Open the next file and bring its content into memeory
		if oCtx.curFileNum >= uint32(len(oCtx.files)) {

			// If reading file names from a queue, try to
			// get more files first. Otherwise, return EOF.
			if oCtx.openMode == sqsMode {
				err = oCtx.getMoreSQSFiles()
				if err != nil {
					return err
				}

				// If after trying, there are no
				// additional files, return timeout.
				if oCtx.curFileNum >= uint32(len(oCtx.files)) {
					return sdk.ErrTimeout
				}
			} else {
				return sdk.ErrEOF
			}
		}

		file := oCtx.files[oCtx.curFileNum]
		oCtx.curFileNum++

		switch oCtx.openMode {
		case s3Mode, sqsMode:
			tmpStr, err = oCtx.readNextFileS3()
		case fileMode:
			tmpStr, err = readFileLocal(file.name)
		}
		if err != nil {
			return err
		}

		// The file can be gzipped. If it is, we unzip it.
		if file.isCompressed {
			gr, err := gzip.NewReader(bytes.NewBuffer(tmpStr))
			if err != nil {
				return sdk.ErrTimeout
			}
			defer gr.Close()
			zdata, err := ioutil.ReadAll(gr)
			if err != nil {
				return sdk.ErrTimeout
			}
			tmpStr = zdata
		}

		// Cloudtrail files have the following format:
		// {"Records":[
		//	{<evt1>},
		//	{<evt2>},
		//	...
		// ]}
		// Here, we split the file content into substrings, one per event.
		// We do this instead of unmarshaling the whole file because this allows
		// us to pass the original json of each event to the engine without an
		// additional marshaling, making things much faster.
		oCtx.evtJSONStrings = nil
		extractRecordStrings(tmpStr, &(oCtx.evtJSONStrings))

		oCtx.evtJSONListPos = 0
	}

	// Extract the next record
	var cr *fastjson.Value
	if len(oCtx.evtJSONStrings) != 0 {
		evtData = oCtx.evtJSONStrings[oCtx.evtJSONListPos]
		cr, err = oCtx.nextJParser.Parse(string(evtData))
		if err != nil {
			// Not json? Just skip this event.
			oCtx.evtJSONListPos++
			return sdk.ErrTimeout
		}

		oCtx.evtJSONListPos++
	} else {
		// Json not int the expected format. Just skip this event.
		return sdk.ErrTimeout
	}
	// All cloudtrail events should have a time. If it's missing
	// skip the event.

	timeVal := cr.GetStringBytes("eventTime")

	if timeVal == nil {
		return sdk.ErrTimeout
	}

	// Extract the timestamp
	t1, err := time.Parse(
		time.RFC3339,
		string(timeVal))
	if err != nil {
		//
		// We assume this is just some spurious data and we continue
		//
		return sdk.ErrTimeout
	}
	evt.SetTimestamp(uint64(t1.UnixNano()))

	// All cloudtrail events should have a type. If it's missing
	// skip the event.

	typeVal := cr.GetStringBytes("eventType")

	if typeVal == nil {
		return sdk.ErrTimeout
	}

	ets := string(typeVal)
	if ets == "AwsCloudTrailInsight" {
		return sdk.ErrTimeout
	}

	// Write the event data
	n, err := evt.Writer().Write(evtData)
	if err != nil {
		return err
	} else if n < len(evtData) {
		return fmt.Errorf("cloudwatch message too long: %d, but %d were written", len(evtData), n)
	}

	return nil
}
