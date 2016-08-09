#!/usr/bin/env_ruby

require 'aws-sdk'
require 'syslog/logger'

# Class for asset management.
class Asset
  def initialize(bucket, key, target)
    @bucket = bucket
    @key = key

    @s3 = Aws::S3::Client.new
    @target = target

    @log = Syslog::Logger.new('s3-virusscan')
  end

  def persist_local
    @log.debug("persisting s3://#{@bucket}/#{@key} to #{@target}")
    begin
      @s3.get_object(response_target: @target, bucket: @bucket, key: @key)
    rescue Aws::S3::Errors::NoSuchKey
      @log.debug("s3://#{@bucket}/#{@key} no longer exists. Skipping...")
      next
    end
  end

  # Delete the asset in s3.
  def delete_remote
    @s3.delete_object(bucket: @bucket, key: @key)
  rescue StandardError => ex
    @log.error("Caught #{ex.class} error calling delete_object on #{@key}.")
  end

  def delete_local
    system("rm #{@target}")
  end
end

