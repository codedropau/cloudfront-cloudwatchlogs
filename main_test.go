package main

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseLogGroupAndStream(t *testing.T) {
	logGroup, logStream := parseLogGroupAndStream("/codedropau/my-cluster/my-project/dev/E38J4Y0L8GXH9D.2020-06-08-07.d51ccc94.gz")

	assert.Equal(t, "/codedropau/my-cluster/my-project/dev", logGroup)
	assert.Equal(t, "E38J4Y0L8GXH9D.2020-06-08-07.d51ccc94", logStream)

	// Make sure logGroup gets prefixed with a /.
	logGroup, _ = parseLogGroupAndStream("codedropau/my-cluster/my-project/prod/E38J4Y0L8GXH9D.2020-06-08-07.d51ccc94.gz")
	assert.Equal(t, "/codedropau/my-cluster/my-project/prod", logGroup)
}

func TestParseLines(t *testing.T) {
	contents, _ := ioutil.ReadFile("./fixtures/test-logs.gz")
	logEvents, err := parseLines(contents)
	assert.Nil(t, err)
	// Length should be number of lines minus 2 for the comments at the top.
	assert.Equal(t, 58, len(logEvents))
	// Log date should be converted to a timestamp.
	assert.Equal(t, int64(1592451493000), *logEvents[0].Timestamp)
	// Logs are sorted in chronilogical order.
	assert.Less(t, *logEvents[0].Timestamp, *logEvents[len(logEvents)-1].Timestamp)
}

func TestParseDateAndMessage(t *testing.T) {
	line := "2020-06-18	03:38:13	SYD4-C2	35207	111.111.11.1	GET	asdasdasd.cloudfront.net	/admin/people	200	https://example.com/home	Mozilla/5.0%20(Macintosh;%20Intel%20Mac%20OS%20X%2010_14_5)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/83.0.4103.97%20Safari/537.36	-	-	Miss	oe49fbR4FcmNWieL3CVBnkQFZiNls0O9Zg24IfUYPWOXMX36hqQI4g==	dev.snsw-cos.snsw.codedropau.dev	https	45	0.301	-	TLSv1.2	ECDHE-RSA-AES128-GCM-SHA256	Miss	HTTP/2.0	-	-	57856	0.299	Miss	text/html;%20charset=UTF-8	-	-	-"
	expectedDate, _ := time.Parse("2006-01-02 15:04:05", "2020-06-18 03:38:13")
	date, message, err := parseDateAndMessage(line)
	assert.Nil(t, err)
	assert.Equal(t, expectedDate, date)
	expectedMessage := "SYD4-C2	35207	111.111.11.1	GET	asdasdasd.cloudfront.net	/admin/people	200	https://example.com/home	Mozilla/5.0%20(Macintosh;%20Intel%20Mac%20OS%20X%2010_14_5)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/83.0.4103.97%20Safari/537.36	-	-	Miss	oe49fbR4FcmNWieL3CVBnkQFZiNls0O9Zg24IfUYPWOXMX36hqQI4g==	dev.snsw-cos.snsw.codedropau.dev	https	45	0.301	-	TLSv1.2	ECDHE-RSA-AES128-GCM-SHA256	Miss	HTTP/2.0	-	-	57856	0.299	Miss	text/html;%20charset=UTF-8	-	-	-"
	assert.Equal(t, expectedMessage, message)
}
