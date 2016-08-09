#!/usr/bin/env ruby

require 'aws-sdk'
require 'json'
require 'syslog/logger'
require 'uri'
require 'yaml'

require './asset.rb'
require './scanner.rb'

TEMP_FILE = '/tmp/target'.freeze
log = Syslog::Logger.new('s3-virusscan')
conf = YAML.load_file(__dir__ + '/s3-virusscan.conf')

# Update the aws config with the s3-virusscan.conf.
Aws.config.update(region: conf['region'])

sns = Aws::SNS::Client.new

poller = Aws::SQS::QueuePoller.new(conf['queue'])

log.info('s3-virusscan started')

poller.poll do |msg|
  body = JSON.parse(msg.body)
  next unless body.key?('Records')

  # Scan each record available.
  body['Records'].each do |record|
    bucket = record['s3']['bucket']['name']
    key = URI.decode(record['s3']['object']['key']).tr('+', ' ')
    asset = Asset.new(bucket, key, TEMP_FILE, log)

    # Set bucket and key for getting a bucket item.
    asset.persist_local

    next if Scanner.new.virus?(bucket, key, TEMP_FILE, log)
    # Scan the asset.
    message = "s3://#{bucket}/#{key} is infected"
    message = "s3://#{bucket}/#{key} is infected, deleting..." if conf['delete']
    log.error(message)

    # Delete the asset.
    if conf['delete']
      log.error("s3://#{bucket}/#{key} was deleted")
      Asset.delete_remote
    end

    # Publish to the SNS topic.
    sns.publish(
      topic_arn: conf['topic'],
      message: message,
      subject: "s3-virusscan s3://#{bucket}",
      message_attributes: {
        'key' => {
          data_type: 'String',
          string_value: "s3://#{bucket}/#{key}"
        }
      }
    )
  end
end
