package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/prometheus/common/log"

	"github.com/codedropau/cloudfront-cloudwatchlogs/internal/aws/cloudwatchlogs/logger"
)

// rateLimit of how many logs per second we can push. See https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html
const rateLimit = time.Second / 800

func main() {
	lambda.Start(HandleEvents)
}

// HandleEvents sent from AWS S3.
func HandleEvents(ctx context.Context, event events.S3Event) error {
	sess, err := session.NewSession()
	if err != nil {
		return fmt.Errorf("failed to setup client: %d", err)
	}
	for _, record := range event.Records {
		fmt.Printf("[%s - %s] Bucket = %s, Key = %s \n", record.EventSource, record.EventTime, record.S3.Bucket.Name, record.S3.Object.Key)
		err := handleEvent(ctx, s3.New(sess), cloudwatchlogs.New(sess), record)
		if err != nil {
			return err
		}
	}
	return nil
}

// Helper function to handle a single S3 event.
func handleEvent(ctx context.Context, s3client s3iface.S3API, cwclient cloudwatchlogsiface.CloudWatchLogsAPI, record events.S3EventRecord) error {
	l := log.NewLogger(os.Stderr)

	// Download the file.
	l.Infof("Downloading %s from %s", record.S3.Object.Key, record.S3.Bucket.Name)
	downloadIn := &s3.GetObjectInput{
		Bucket: aws.String(record.S3.Bucket.Name),
		Key:    aws.String(record.S3.Object.Key),
	}
	downloader := s3manager.NewDownloaderWithClient(s3client)
	buffRaw := &aws.WriteAtBuffer{}
	_, err := downloader.DownloadWithContext(ctx, buffRaw, downloadIn)
	if err != nil {
		return fmt.Errorf("unable to download log file: %v", err)
	}
	// Parse out lines.
	lines, err := parseLines(buffRaw.Bytes())
	if err != nil {
		return err
	}
	l.Infof("Pushing %d logs to CloudWatch", len(lines))

	logGroup, logStream := parseLogGroupAndStream(record.S3.Object.Key)
	cwLogger, err := logger.New(cwclient, logGroup, logStream, 256)
	if err != nil {
		return err
	}
	throttle := time.Tick(rateLimit)
	for _, line := range lines {
		<-throttle
		err = cwLogger.Add(line)
		if err != nil {
			return err
		}
	}

	return cwLogger.Flush()
}

// parseLines from a gzip file contents.
func parseLines(contents []byte) ([]*cloudwatchlogs.InputLogEvent, error) {
	buff := bytes.Buffer{}
	err := gunzipWrite(&buff, contents)
	if err != nil {
		return []*cloudwatchlogs.InputLogEvent{}, err
	}

	// Split the file by newline.
	split := []byte("\n")
	lines := bytes.Split(buff.Bytes(), split)
	messages := make([]*cloudwatchlogs.InputLogEvent, 0)

	// Loop over the lines and parse out the timestamp and message.
	for _, line := range lines {
		if len(line) < 1 {
			// Nothing in this line - probably just a newline.
			continue
		}
		message := string(line)
		if strings.HasPrefix(string(message), "#") {
			// Comment - ignore.
			continue
		}
		// Parse date out of cloudfront access log line.
		date, message, err := parseDateAndMessage(message)
		if err != nil {
			// Couldn't parse date, default to now.
			date = time.Now()
		}
		messages = append(messages, &cloudwatchlogs.InputLogEvent{
			Message:   aws.String(message),
			Timestamp: aws.Int64(aws.TimeUnixMilli(date)),
		})
	}

	// Sort the messages chronologically.
	sort.Slice(messages, func(i, j int) bool {
		a := *messages[i].Timestamp
		b := *messages[j].Timestamp
		return a < b
	})

	return messages, nil
}

// gunzipWrite a gzip file to a buffer.
func gunzipWrite(w io.Writer, data []byte) error {
	gr, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer gr.Close()

	data, err = ioutil.ReadAll(gr)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// parseDateAndMessage from a cloudfront log string.
func parseDateAndMessage(line string) (time.Time, string, error) {
	// #Fields: date date x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status cs(Referer) cs(User-Agent) cs-uri-query cs(Cookie) x-edge-result-type x-edge-request-id x-host-header cs-protocol cs-bytes date-taken x-forwarded-for ssl-protocol ssl-cipher x-edge-response-result-type cs-protocol-version fle-status fle-encrypted-fields
	// 2014-05-23 01:13:11 FRA2 182 192.0.2.10 GET d111111abcdef8.cloudfront.net /view/my/file.html 200 www.displaymyfiles.com Mozilla/4.0%20(compatible;%20MSIE%205.0b1;%20Mac_PowerPC) - zip=98101 RefreshHit MRVMF7KydIvxMWfJIglgwHQwZsbG2IhRJ07sn9AkKUFSHS9EXAMPLE== d111111abcdef8.cloudfront.net http - 0.001 - - - RefreshHit HTTP/1.1 Processed 1

	// Grab the first two components of the line.
	sep := "\t"
	lineParts := strings.SplitN(line, sep, 3)
	if len(lineParts) < 3 {
		return time.Time{}, "", errors.New("unable to parse date")
	}
	layout := "2006-01-02 15:04:05"
	date, err := time.Parse(layout, fmt.Sprintf("%s %s", lineParts[0], lineParts[1]))

	// Join the rest of the message back together.
	message := strings.Join(lineParts[2:], sep)

	return date, message, err
}

// parseLogGroupAndStream from the s3 object key.
func parseLogGroupAndStream(key string) (string, string) {
	var (
		logGroup  string
		logStream string
	)
	sep := "/"
	// Split the key up by slash.
	keyParts := strings.Split(key, sep)
	// Filename is the last part of the key.
	filename := keyParts[len(keyParts)-1]
	// LogGroup is the whole key excluding the filename.
	logGroup = strings.Join(keyParts[:len(keyParts)-1], sep)
	// Ensure the logGroup is prefixed with a slash.
	if !strings.HasPrefix(logGroup, "/") {
		logGroup = fmt.Sprintf("/%s", logGroup)
	}
	// LogStream is all parts of the filename without the extension.
	sep = "."
	filenameParts := strings.Split(filename, sep)
	logStream = strings.Join(filenameParts[:len(filenameParts)-1], sep)
	return logGroup, logStream
}
