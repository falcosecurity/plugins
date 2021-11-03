package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/valyala/fastjson"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

func dirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func openLocal(pCtx *pluginContext, oCtx *openContext, params string) error {
	oCtx.openMode = fileMode

	oCtx.cloudTrailFilesDir = params

	if len(oCtx.cloudTrailFilesDir) == 0 {
		return fmt.Errorf(PluginName + " plugin error: missing input directory argument")
	}

	if !dirExists(oCtx.cloudTrailFilesDir) {
		return fmt.Errorf(PluginName+" plugin error: cannot open %s", oCtx.cloudTrailFilesDir)
	}

	log.Printf("[%s] scanning directory %s\n", PluginName, oCtx.cloudTrailFilesDir)

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

	log.Printf("[%s] found %d json files\n", PluginName, len(oCtx.files))
	return nil
}

func initS3(oCtx *openContext) {
	oCtx.s3.awsSess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	oCtx.s3.awsSvc = s3.New(oCtx.s3.awsSess)

	oCtx.s3.downloader = s3manager.NewDownloader(oCtx.s3.awsSess)
}

func openS3(pCtx *pluginContext, oCtx *openContext, input string) error {
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

	initS3(oCtx)

	// Fetch the list of keys

	err := oCtx.s3.awsSvc.ListObjectsPages(&s3.ListObjectsInput{
		Bucket: &oCtx.s3.bucket,
		Prefix: &prefix,
	}, func(p *s3.ListObjectsOutput, last bool) (shouldContinue bool) {
		for _, obj := range p.Contents {
			//fmt.Printf("> %v %v\n", *obj.Size, *obj.Key)
			path := obj.Key
			isCompressed := strings.HasSuffix(*path, ".json.gz")
			if filepath.Ext(*path) != ".json" && !isCompressed {
				continue
			}

			var fi fileInfo = fileInfo{name: *path, isCompressed: true}
			oCtx.files = append(oCtx.files, fi)
		}
		return true
	})
	if err != nil {
		err = fmt.Errorf(PluginName + " plugin error: failed to list objects: " + err.Error())
	}

	return err
}

func getMoreSQSFiles(pCtx *pluginContext, oCtx *openContext) error {
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

	if pCtx.sqsDelete {
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

	var notification snsMessage

	err = json.Unmarshal([]byte(sqsMsg["Message"].(string)), &notification)

	if err != nil {
		return err
	}

	// The notification contains a bucket and a list of keys that
	// contain new cloudtrail files.
	oCtx.s3.bucket = notification.Bucket

	initS3(oCtx)

	for _, key := range notification.Keys {

		isCompressed := strings.HasSuffix(key, ".json.gz")

		oCtx.files = append(oCtx.files, fileInfo{name: key, isCompressed: isCompressed})
	}

	return nil
}

func openSQS(pCtx *pluginContext, oCtx *openContext, input string) error {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	oCtx.openMode = sqsMode

	oCtx.sqsClient = sqs.NewFromConfig(cfg)

	queueName := input[6:]

	urlResult, err := oCtx.sqsClient.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: &queueName})

	if err != nil {
		return err
	}

	oCtx.queueURL = *urlResult.QueueUrl

	return getMoreSQSFiles(pCtx, oCtx)
}

var dlErrChan chan error

func s3Download(oCtx *openContext, downloader *s3manager.Downloader, name string, dloadSlotNum int) {
	defer oCtx.s3.DownloadWg.Done()

	buff := &aws.WriteAtBuffer{}
	_, err := downloader.Download(buff,
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

func readNextFileS3(pCtx *pluginContext, oCtx *openContext) ([]byte, error) {
	if oCtx.s3.curBuf < oCtx.s3.nFilledBufs {
		curBuf := oCtx.s3.curBuf
		oCtx.s3.curBuf++
		return oCtx.s3.DownloadBufs[curBuf], nil
	}

	dlErrChan = make(chan error, pCtx.s3DownloadConcurrency)
	k := oCtx.s3.lastDownloadedFileNum
	oCtx.s3.nFilledBufs = min(pCtx.s3DownloadConcurrency, len(oCtx.files)-k)
	for j, f := range oCtx.files[k : k+oCtx.s3.nFilledBufs] {
		oCtx.s3.DownloadWg.Add(1)
		go s3Download(oCtx, oCtx.s3.downloader, f.name, j)
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
func nextEvent(pCtx *pluginContext, oCtx *openContext, evt sdk.EventWriter) error {
	var evtData []byte
	var tmpStr []byte
	var err error

	// Only open the next file once we're sure that the content of the previous one has been full consumed
	if oCtx.evtJSONListPos == len(oCtx.evtJSONStrings) {
		// Open the next file and bring its content into memeory
		if oCtx.curFileNum >= uint32(len(oCtx.files)) {

			// If reading file names from a queue, try to
			// get more files first. Otherwise, return EOF.
			if oCtx.openMode == sqsMode {
				err = getMoreSQSFiles(pCtx, oCtx)
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
			tmpStr, err = readNextFileS3(pCtx, oCtx)
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
		oCtx.evtJSONListPos++
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
