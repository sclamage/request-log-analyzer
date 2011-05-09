require 'request_log_analyzer/file_format/haproxy'

module RequestLogAnalyzer::FileFormat

  class HaproxyNoQuery < Haproxy

    # substitute version specific parts of the haproxy entry regexp.
    def self.compose_regexp(millisecs, backends, counters, connections, queues)
      %r{
        (#{ip_address}):\d+\s # client_ip ':' client_port
        \[(#{timestamp('%d/%b/%Y:%H:%M:%S')})#{millisecs}\]\s # '[' accept_date ']'
        (\S+)\s # frontend_name
        #{backends}
        #{counters}
        (\d+)\s # status_code
        \+?(\d+)\s # bytes_read
        (\S+)\s # captured_request_cookie
        (\S+)\s # captured_response_cookie
        (\w|-)(\w|-)(\w|-)(\w|-)\s # termination_state
        #{connections}
        #{queues}
        (\S*)\s? # captured_request_headers
        (\S*)\s? # captured_response_headers
        "([^"?]*)[^"]*" # '"' http_request without query string'"'
      }x
    end

    # Define line types

    # line definition for haproxy 1.3 and higher
    line_definition :haproxy13 do |line|
      line.header = true
      line.footer = true
      line.teaser = /\.\d{3}\] \S+ \S+\/\S+ / # .millisecs] frontend_name backend_name/server_name

      line.regexp = compose_regexp(
          '\.\d{3}', # millisecs
          '(\S+)\/(\S+)\s', # backend_name '/' server_name
          '(\d+|-1)\/(\d+|-1)\/(\d+|-1)\/(\d+|-1)\/\+?(\d+)\s', # Tq '/' Tw '/' Tc '/' Tr '/' Tt
          '(\d+)\/(\d+)\/(\d+)\/(\d+)\/\+?(\d+)\s', # actconn '/' feconn '/' beconn '/' srv_conn '/' retries
          '(\d+)\/(\d+)\s' # srv_queue '/' backend_queue
      )

      line.capture(:client_ip).as(:string)
      line.capture(:timestamp).as(:timestamp)
      line.capture(:frontend_name).as(:string)
      line.capture(:backend_name).as(:string)
      line.capture(:server_name).as(:string)
      line.capture(:tq).as(:nillable_duration, :unit => :msec)
      line.capture(:tw).as(:nillable_duration, :unit => :msec)
      line.capture(:tc).as(:nillable_duration, :unit => :msec)
      line.capture(:tr).as(:nillable_duration, :unit => :msec)
      line.capture(:tt).as(:duration, :unit => :msec)
      line.capture(:status_code).as(:integer)
      line.capture(:bytes_read).as(:traffic, :unit => :byte)
      line.capture(:captured_request_cookie).as(:nillable_string)
      line.capture(:captured_response_cookie).as(:nillable_string)
      line.capture(:termination_event_code).as(:nillable_string)
      line.capture(:terminated_session_state).as(:nillable_string)
      line.capture(:clientside_persistence_cookie).as(:nillable_string)
      line.capture(:serverside_persistence_cookie).as(:nillable_string)
      line.capture(:actconn).as(:integer)
      line.capture(:feconn).as(:integer)
      line.capture(:beconn).as(:integer)
      line.capture(:srv_conn).as(:integer)
      line.capture(:retries).as(:integer)
      line.capture(:srv_queue).as(:integer)
      line.capture(:backend_queue).as(:integer)
      line.capture(:captured_request_headers).as(:nillable_string)
      line.capture(:captured_response_headers).as(:nillable_string)
      line.capture(:http_request).as(:nillable_string)
    end

    # haproxy 1.2 has a few fields less than 1.3+
    line_definition :haproxy12 do |line|
      line.header = true
      line.footer = true
      line.teaser = /\.\d{3}\] \S+ \S+ / # .millisecs] frontend_name server_name

      line.regexp = compose_regexp(
          '\.\d{3}', # millisecs
          '(\S+)\s', # server_name
          '(\d+|-1)\/(\d+|-1)\/(\d+|-1)\/(\d+|-1)\/\+?(\d+)\s', # Tq '/' Tw '/' Tc '/' Tr '/' Tt
          '(\d+)\/(\d+)\/(\d+)\s', # srv_conn '/' listener_conn '/' process_conn
          '(\d+)\/(\d+)\s' # srv_queue '/' backend_queue
      )

      line.capture(:client_ip).as(:string)
      line.capture(:timestamp).as(:timestamp)
      line.capture(:frontend_name).as(:string)
      line.capture(:server_name).as(:string)
      line.capture(:tq).as(:nillable_duration, :unit => :msec)
      line.capture(:tw).as(:nillable_duration, :unit => :msec)
      line.capture(:tc).as(:nillable_duration, :unit => :msec)
      line.capture(:tr).as(:nillable_duration, :unit => :msec)
      line.capture(:tt).as(:duration, :unit => :msec)
      line.capture(:status_code).as(:integer)
      line.capture(:bytes_read).as(:traffic, :unit => :byte)
      line.capture(:captured_request_cookie).as(:nillable_string)
      line.capture(:captured_response_cookie).as(:nillable_string)
      line.capture(:termination_event_code).as(:nillable_string)
      line.capture(:terminated_session_state).as(:nillable_string)
      line.capture(:clientside_persistence_cookie).as(:nillable_string)
      line.capture(:serverside_persistence_cookie).as(:nillable_string)
      line.capture(:srv_conn).as(:integer)
      line.capture(:listener_conn).as(:integer)
      line.capture(:process_conn).as(:integer)
      line.capture(:srv_queue).as(:integer)
      line.capture(:backend_queue).as(:integer)
      line.capture(:captured_request_headers).as(:nillable_string)
      line.capture(:captured_response_headers).as(:nillable_string)
      line.capture(:http_request).as(:nillable_string)
    end

    # and haproxy 1.1 has even less fields
    line_definition :haproxy11 do |line|
      line.header = true
      line.footer = true
      line.teaser = /:\d{2}\] \S+ \S+ / # :secs] frontend_name server_name

      line.regexp = compose_regexp(
          '', # no millisec precision in this version of haproxy
          '(\S+)\s', # server_name
          '(\d+|-1)\/(\d+|-1)\/(\d+|-1)\/\+?(\d+)\s', # Tq '/' Tc '/' Tr '/' Tt
          '(\d+)\/(\d+)\s', # listener_conn '/' process_conn
          '' # no queues in this version of haproxy
      )

      line.capture(:client_ip).as(:string)
      line.capture(:timestamp).as(:timestamp)
      line.capture(:frontend_name).as(:string)
      line.capture(:server_name).as(:string)
      line.capture(:tq).as(:nillable_duration, :unit => :msec)
      line.capture(:tc).as(:nillable_duration, :unit => :msec)
      line.capture(:tr).as(:nillable_duration, :unit => :msec)
      line.capture(:tt).as(:duration, :unit => :msec)
      line.capture(:status_code).as(:integer)
      line.capture(:bytes_read).as(:traffic, :unit => :byte)
      line.capture(:captured_request_cookie).as(:nillable_string)
      line.capture(:captured_response_cookie).as(:nillable_string)
      line.capture(:termination_event_code).as(:nillable_string)
      line.capture(:terminated_session_state).as(:nillable_string)
      line.capture(:clientside_persistence_cookie).as(:nillable_string)
      line.capture(:serverside_persistence_cookie).as(:nillable_string)
      line.capture(:listener_conn).as(:integer)
      line.capture(:process_conn).as(:integer)
      line.capture(:srv_queue).as(:integer)
      line.capture(:backend_queue).as(:integer)
      line.capture(:captured_request_headers).as(:nillable_string)
      line.capture(:captured_response_headers).as(:nillable_string)
      line.capture(:http_request).as(:nillable_string)
    end
  end
end
