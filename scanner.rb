#!/usr/bin/env_ruby

require 'digest'
require 'uirusu'

module Scanner
  # Returns true if any of the scanners find a virus; otherwise return false.
  # Scan the target and check the result's exit status.
  def self.virus?(bucket, key, target, log)
    has_viruses = false
    log.debug("scanning s3://#{bucket}/#{key} with clamav...")
    self.clam_result = clam_scan(target)
    case
    when clam_result == 0
      log.debug("s3://#{bucket}/#{key} was scanned with clamav without findings")
      log.debug("s3://#{bucket}/#{key} now scanning via virustotal")
    when clam_result == 1
      has_viruses = true
    else
      log.debug("ClamAV had an issue and couldn't/didn't scan the file. Skipped #{key}")
    end
    return has_viruses
  end

  private
  def self.clam_scan(target)
    system("clamscan --max-filesize=100M --max-scansize=500M #{target}")
    return $?.exitstatus
  end
end

