#!/usr/bin/env ruby

require 'aws-sdk'
require 'digest'
require 'json'
require 'rest-client'
require 'syslog/logger'
require 'uirusu'
require 'uri'
require 'yaml'

TEMP_FILE = '/tmp/target'
log = Syslog::Logger.new 's3-virusscan'
conf = YAML::load_file(__dir__ + '/s3-virusscan.conf')

Aws.config.update(region: conf['region'])
s3 = Aws::S3::Client.new()
sns = Aws::SNS::Client.new()

poller = Aws::SQS::QueuePoller.new(conf['queue'])

log.info "s3-virusscan started"

# Ensure scannable object exists.
def persist_asset(bucket, key, response_target)
  log.debug("persisting s3://#{bucket}/#{key} to #{TEMP_FILE}")
  begin
    s3.get_object(response_target: response_target, bucket: bucket, key: key)
  rescue Aws::S3::Errors::NoSuchKey
    log.debug("s3://#{bucket}/#{key} no longer exists. Skipping...")
    next
  end
end

# Returns 0 for no virus, 1 for virus found and 2 for file processing error.
# Scan the asset using a system call to clamav.
def clam_scan(target)
  system("clamscan --max-filesize=100M --max-scansize=500M #{target}")
  return $?.exitstatus
end

# Returns true if any of the scanners find a virus; otherwise return false.
# Scan the target and check the result's exit status.
def virus?(bucket, key, target)
  has_viruses = false
  log.debug("scanning s3://#{bucket}/#{key} with clamav...")
  clam_result = clam_scan(target)
  case
  when clam_result == 0
    log.debug("s3://#{bucket}/#{key} was scanned without findings")
    log.debug("s3://#{bucket}/#{key} now scanning via virustotal")
  when clam_result == 1
    has_viruses = true
  else
    log.debug("ClamAV had an issue and couldn't/didn't scan the file. Skipped #{key}")
  end
  return has_viruses
end

def delete_asset(bucket, key)
  begin
    # Go ahead and delete malicious object.
    s3.delete_object(bucket: bucket, key: key)
    log.error("s3://#{bucket}/#{key} was deleted")
  rescue Exception => ex
    log.error("Caught #{ex.class} error calling delete_object on #{key}. De-queueing anyway.")
  end
end

poller.poll do |msg|
  body = JSON.parse(msg.body)
  next if !body.key?('Records')

  # Scan each record available.
  body['Records'].each do |record|
    # Set bucket and key for getting a bucket item.
    bucket = record['s3']['bucket']['name']
    key = URI.decode(record['s3']['object']['key']).gsub('+', ' ')

    persist_asset(bucket, key, TEMP_FILE)
    has_virus = scan_asset(bucket, key, TEMP_FILE)

    if virus?(bucket, key, TEMP_FILE)
      message = conf['delete'] ? "s3://#{bucket}/#{key} is infected, deleting..." : "s3://#{bucket}/#{key} is infected"
      log.error(message)

      # Delete the asset.
      delete_asset(bucket, key) if conf['delete']

      # Publish to the SNS topic.
      sns.publish(
        topic_arn: conf['topic'],
        message: message,
        subject: "s3-virusscan s3://#{bucket}",
        message_attributes: {
          "key" => {
            data_type: "String",
            string_value: "s3://#{bucket}/#{key}"
          }
        }
      )
    end
    system("rm #{TEMP_FILE}")
  end
end

