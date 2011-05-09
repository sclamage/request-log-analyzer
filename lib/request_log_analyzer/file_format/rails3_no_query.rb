require 'request_log_analyzer/file_format/rails3'

module RequestLogAnalyzer::FileFormat

  class Rails3NoQuery < Rails3

    extend CommonRegularExpressions

    line_definition :started do |line|
      line.header = true
      line.teaser = /Started /
      line.regexp = /Started ([A-Z]+) "([^?"]+[^"]*)" for (#{ip_address}) at (#{timestamp('%a %b %d %H:%M:%S %z %Y')}|#{timestamp('%Y-%m-%d %H:%M:%S %z')})/
      
      line.capture(:method)
      line.capture(:path)
      line.capture(:ip)
      line.capture(:timestamp).as(:timestamp)
    end
  end
end
