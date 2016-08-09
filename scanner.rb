#!/usr/bin/env_ruby

require 'digest'
require 'uirusu'
require 'syslog/logger'
require 'English'

# Class for scanning assets for viruses.
class Scanner
  def initialize
    @log = Syslog::Logger
  end

  def virus?(bucket, key, target)
    self.clam_result = clam_scan(target)
    if clam_result.zero?
      @log.debug("s3://#{bucket}/#{key} was scanned with clamav: nothing found")
      @log.debug("s3://#{bucket}/#{key} now scanning via virustotal")
    elsif clam_result == 1
      true
    else
      @log.debug("Error: ClamAV couldn't scan the file. Skipped #{key}")
    end
    false
  end

  def clam_scan(target)
    @log.debug("scanning s3://#{bucket}/#{key} with clamav...")
    system("clamscan --max-filesize=100M --max-scansize=500M #{target}")
    $CHILD_STATUS.exitstatus
  end
end
