package watchqueue

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/prometheus/common/log"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/skpr/cloudfront-cloudwatchlogs/internal/discovery"
	"github.com/skpr/cloudfront-cloudwatchlogs/internal/watcher"
)

const (
	DefaultRegion           string = "ap-southeast-2"
	DefaultTagNameLogGroup  string = "edge.skpr.io/loggroup"
	DefaultTagNameLogStream string = "edge.skpr.io/logstream"
	DefaultVerbosity	    string = "debug"
)

type cmdWatch struct {
	// Region defines the cloudwatch region.
	Region string

	TagNameLogGroup  string
	TagNameLogStream string
}

func (cmd *cmdWatch) run(c *kingpin.ParseContext) error {
	logger := log.NewLogger(os.Stderr).With("region", cmd.Region)
	_ = logger.SetLevel(DefaultVerbosity)
	logger.Debug("initialising")

	config := &aws.Config{
		Region: aws.String(cmd.Region),
	}
	sess, err := session.NewSession(config)
	if err != nil {
		return errors.Wrap(err, "unable to initialise aws session")
	}
	clientCloudfront := cloudfront.New(sess)
	clientS3 := s3.New(sess)
	clientSqs := sqs.New(sess)
	clientCloudwatch := cloudwatchlogs.New(sess)

	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Look up cloudfront distributions with relevant tags.
	logger.Debug("starting cloudfront distribution discovery")
	distributions, err := discovery.GetDistributionsWithTags(clientCloudfront, []string{
		cmd.TagNameLogGroup,
		cmd.TagNameLogStream,
	})
	if err != nil {
		return err
	}

	watchers := make([]watcher.Watcher, 0)
	for _, item := range distributions {
		distlogger := logger.With("distribution", *item.DistributionSummary.Id)
		w := watcher.Watcher{
			Logger:           distlogger,
			Wg:               wg,
			ClientS3:         clientS3,
			ClientSQS:        clientSqs,
			ClientCloudwatch: clientCloudwatch,
			DistributionId:   item.DistributionSummary.Id,
		}
		distlogger.Info("candidate distribution found")

		for _, tag := range item.Tags.Items {
			distlogger.Debugf("tag found '%s': '%s'", *tag.Key, *tag.Value)
			switch *tag.Key {
			case cmd.TagNameLogGroup:
				w.LogGroup = tag.Value

			case cmd.TagNameLogStream:
				w.LogStream = tag.Value
			}
		}

		if w.LogStream == nil {
			// Default logStream if it not specified in the resource tags.
			distlogger.Debug("using default logStream name")
			w.LogStream = aws.String(fmt.Sprintf("cloudfront-%s", *item.DistributionSummary.Id))
		}

		in := &discovery.GetDistributionLogQueueInput{
			ClientS3:         clientS3,
			ClientCloudfront: clientCloudfront,
			Distribution:     item.DistributionSummary,
		}
		queue, err := discovery.GetDistributionLogQueue(in)
		if err != nil {
			distlogger.Errorf("couldnt find sqs queue for distribution logs")
			continue
		}

		w.QueueARN = queue
		distlogger.Debugf("sqs queue for logs is %s", *queue)
		watchers = append(watchers, w)
	}

	// Look up SQS queue.
	wg.Add(len(watchers))
	for _, w := range watchers {
		go w.Watch(ctx)
	}
	wg.Wait()

	// @todo add a refresh which kills running go routines and re-runs discovery.

	fmt.Println("done")
	return nil
}

// Cmd declares the "watch" sub command.
func Cmd(app *kingpin.Application) {
	cmd := new(cmdWatch)
	c := app.Command("watch", "Discover CloudFront distributions with logging configured").Action(cmd.run)
	c.Flag("region", "AWS region for discovery").Default(DefaultRegion).
		Envar("AWS_REGION").
		StringVar(&cmd.Region)
	c.Flag("tag-group", "Tag name on cloudfront distribution to use for log group").
		Default(DefaultTagNameLogGroup).
		StringVar(&cmd.TagNameLogGroup)
	c.Flag("tag-stream", "Tag name on cloudfront distribution to use for log stream").
		Default(DefaultTagNameLogStream).
		StringVar(&cmd.TagNameLogStream)
}
