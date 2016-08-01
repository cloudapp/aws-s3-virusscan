#!/usr/bin/env ruby

require 'aws-sdk'
require 'json'
require 'uri'
require 'yaml'
require 'syslog/logger'

log = Syslog::Logger.new 's3-virusscan'
conf = YAML::load_file(__dir__ + '/s3-virusscan.conf')

Aws.config.update(region: conf['region'])
s3 = Aws::S3::Client.new()
sns = Aws::SNS::Client.new()

poller = Aws::SQS::QueuePoller.new(conf['queue'])

log.info "s3-virusscan started"

poller.poll do |msg|
  body = JSON.parse(msg.body)
  if body.key?('Records')
    body['Records'].each do |record|
      bucket = record['s3']['bucket']['name']
      key = URI.decode(record['s3']['object']['key']).gsub('+', ' ')
      log.debug "scanning s3://#{bucket}/#{key}..."
      begin
        s3.get_object(
          response_target: '/tmp/target',
          bucket: bucket,
          key: key
        )
      rescue Aws::S3::Errors::NoSuchKey
        log.debug "s3://#{bucket}/#{key} does no longer exist"
        next
      end

      result = system('clamscan --max-filesize=100M --max-scansize=500M /tmp/target')
      if result == 0
        log.debug "s3://#{bucket}/#{key} was scanned without findings"
      elsif result ==2
        log.debug "ClamAV had an issue and couldn't/didn't scan the file. Skipped #{key}"
      elsif result == 1
        if conf['delete']
          log.error "s3://#{bucket}/#{key} is infected, deleting..."
          sns.publish(
            topic_arn: conf['topic'],
            message: "s3://#{bucket}/#{key} is infected, deleting...",
            subject: "s3-virusscan s3://#{bucket}",
            message_attributes: {
              "key" => {
                data_type: "String",
                string_value: "s3://#{bucket}/#{key}"
              }
            }
          )
          s3.delete_object(
            bucket: bucket,
            key: key
          )
          log.error "s3://#{bucket}/#{key} was deleted"
        else
          log.error "s3://#{bucket}/#{key} is infected"
          sns.publish(
            topic_arn: conf['topic'],
            message: "s3://#{bucket}/#{key} is infected",
            subject: "s3-virusscan s3://#{bucket}",
            message_attributes: {
              "key" => {
                data_type: "String",
                string_value: "s3://#{bucket}/#{key}"
              }
            }
          )
        end
      end
      system('rm /tmp/target')
    end
  end
end

