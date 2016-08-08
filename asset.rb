#!/usr/bin/env_ruby

require 'aws-sdk'

class Asset

  def initialize(bucket, key, target, log)
    @bucket = bucket
    @key = key

    @s3 = Aws::S3::Client.new()
    @target = target

    # This seems dirty.
    @log = log
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
    begin
      @s3.delete_object(bucket: @bucket, key: @key)
    rescue Exception => ex
      @log.error("Caught #{ex.class} error calling delete_object on #{@key}. De-queueing anyway.")
    end
  end

  def delete_local
    system("rm #{@target}")
  end
end

