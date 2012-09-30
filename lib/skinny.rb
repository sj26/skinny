require 'base64'
require 'eventmachine'
require 'digest/md5'
require 'thin'

module Skinny
  module Callbacks
    def self.included base
      base.class_eval do
        extend ClassMethods
        include InstanceMethods
      end
    end

    module ClassMethods
      def define_callback *names
        names.each do |name|
          define_method name do |&block|
            add_callback name, &block
          end
        end
      end
    end

    module InstanceMethods
      def add_callback name, &block
        @callbacks ||= {}
        @callbacks[name] ||= []
        @callbacks[name] << block
      end

      def callback name, *args, &block
        return [] if @callbacks.nil? || @callbacks[name].nil?
        @callbacks[name].collect { |callback| callback.call *args, &block }
      end
    end
  end

  class WebSocketError < RuntimeError; end
  class WebSocketProtocolError < WebSocketError; end

  # We need to be really careful not to throw an exception too high
  # or we'll kill the server.
  class Websocket < EventMachine::Connection
    include Callbacks
    include Thin::Logging

    define_callback :on_open, :on_start, :on_handshake, :on_message, :on_error, :on_finish, :on_close

    # 4mb is almost too generous, imho.
    MAX_BUFFER_LENGTH = 2 ** 32

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    OPCODE_CONTINUATION = 0x00
    OPCODE_TEXT = 0x01
    OPCODE_BINARY = 0x02
    OPCODE_CLOSE = 0x08
    OPCODE_PING = 0x09
    OPCODE_PONG = 0x0a

    # Create a new WebSocket from a Thin::Request environment
    def self.from_env env, options={}
      # Pull the connection out of the env
      thin_connection = env[Thin::Request::ASYNC_CALLBACK].receiver
      # Steal the IO
      fd = thin_connection.detach
      # EventMachine 1.0.0 needs this to be closable
      io = IO.for_fd(fd) unless fd.respond_to? :close
      # We have all the events now, muahaha
      EM.attach(io, self, env, options)
    end

    def initialize env, options={}
      @env = env.dup
      @buffer = ''

      @protocol = options.delete :protocol if options.has_key? :protocol
      [:on_open, :on_start, :on_handshake, :on_message, :on_error, :on_finish, :on_close].each do |name|
        send name, &options.delete(name) if options.has_key?(name)
      end
      raise ArgumentError, "Unknown options: #{options.inspect}" unless options.empty?
    end

    # Connection is now open
    def post_init
      EM.next_tick { callback :on_open, self rescue error! "Error in open callback" }
      @state = :open
    rescue
      error! "Error opening connection"
    end

    # Return an async response -- stops Thin doing anything with connection.
    def response
      Thin::Connection::AsyncResponse
    end

    # Arrayify self into a response tuple
    alias :to_a :response

    # Start the websocket connection
    def start!
      # Steal any remaining data from rack.input
      @buffer = @env[Thin::Request::RACK_INPUT].read + @buffer

      # Remove references to Thin connection objects, freeing memory
      @env.delete Thin::Request::RACK_INPUT
      @env.delete Thin::Request::ASYNC_CALLBACK
      @env.delete Thin::Request::ASYNC_CLOSE

      # Figure out which version we're using
      @version = @env['HTTP_SEC_WEBSOCKET_VERSION']
      @version ||= "hixie-76" if @env.has_key?('HTTP_SEC_WEBSOCKET_KEY1') and @env.has_key?('HTTP_SEC_WEBSOCKET_KEY2')
      @version ||= "hixie-75"

      # Pull out the details we care about
      @origin ||= @env['HTTP_SEC_WEBSOCKET_ORIGIN'] || @env['HTTP_ORIGIN']
      @location ||= "ws#{secure? ? 's' : ''}://#{@env['HTTP_HOST']}#{@env['REQUEST_PATH']}"
      @protocol ||= @env['HTTP_SEC_WEBSOCKET_PROTOCOL'] || @env['HTTP_WEBSOCKET_PROTOCOL']

      EM.next_tick { callback :on_start, self rescue error! "Error in start callback" }

      # Queue up the actual handshake
      EM.next_tick method :handshake!

      @state = :started

      # Return self so we can be used as a response
      self
    rescue
      error! "Error starting connection"
    end

    attr_reader :env, :version, :origin, :location, :protocol

    def hixie_75?
      @version == "hixie-75"
    end

    def hixie_76?
      @version == "hixie-76"
    end

    def secure?
      @env['HTTPS'] == 'on' or
      # XXX: This could be faked... do we care?
      @env['HTTP_X_FORWARDED_PROTO'] == 'https' or
      @env['rack.url_scheme'] == 'https'
    end

    def key
      @env['HTTP_SEC_WEBSOCKET_KEY']
    end

    [1, 2].each do |i|
      define_method :"key#{i}" do
        key = env["HTTP_SEC_WEBSOCKET_KEY#{i}"]
        key.scan(/[0-9]/).join.to_i / key.count(' ')
      end
    end

    def key3
      @key3 ||= @buffer.slice!(0...8)
    end

    def challenge?
      env.has_key? 'HTTP_SEC_WEBSOCKET_KEY1'
    end

    def challenge
      if hixie_75?
        nil
      elsif hixie_76?
        [key1, key2].pack("N*") + key3
      else
        key + GUID
      end
    end

    def challenge_response
      if hixie_75?
        nil
      elsif hixie_76?
        Digest::MD5.digest(challenge)
      else
        Base64.encode64(Digest::SHA1.digest(challenge)).strip
      end
    end

    # Generate the handshake
    def handshake
      "HTTP/1.1 101 Switching Protocols\r\n" <<
      "Connection: Upgrade\r\n" <<
      "Upgrade: WebSocket\r\n" <<
      if hixie_75?
        "WebSocket-Location: #{location}\r\n" <<
        "WebSocket-Origin: #{origin}\r\n"
      elsif hixie_76?
        "Sec-WebSocket-Location: #{location}\r\n" <<
        "Sec-WebSocket-Origin: #{origin}\r\n"
      else
        "Sec-WebSocket-Accept: #{challenge_response}\r\n"
      end <<
      (protocol ? "Sec-WebSocket-Protocol: #{protocol}\r\n" : "") <<
      "\r\n" <<
      (if hixie_76? then challenge_response else "" end)
    end

    def handshake!
      if hixie_76?
        [key1, key2].each { |key| raise WebSocketProtocolError, "Invalid key: #{key}" if key >= 2**32 }
        raise WebSocketProtocolError, "Invalid challenge: #{key3}" if key3.length < 8
      end

      send_data handshake

      @state = :handshook

      EM.next_tick { callback :on_handshake, self rescue error! "Error in handshake callback" }
    rescue
      error! "Error during WebSocket connection handshake"
    end

    def receive_data data
      @buffer << data

      EM.next_tick { process_frame } if @state == :handshook
    rescue
      error! "Error while receiving WebSocket data"
    end

    def mask payload, mask_key
      payload.unpack("C*").map.with_index do |byte, index|
        byte ^ mask_key[index % 4]
      end.pack("C*")
    end

    def process_frame
      if hixie_75? or hixie_76?
        if @buffer.length >= 1
          if @buffer[0].ord < 0x7f
            if ending = @buffer.index("\xff")
              frame = @buffer.slice! 0..ending
              message = frame[1..-2]

              EM.next_tick { receive_message message }

              # There might be more frames to process
              EM.next_tick { process_frame }
            elsif @buffer.length > MAX_BUFFER_LENGTH
              raise WebSocketProtocolError, "Maximum buffer length (#{MAX_BUFFER_LENGTH}) exceeded: #{@buffer.length}"
            end
          elsif @buffer[0] == "\xff"
            if @buffer.length > 1
              if @buffer[1] == "\x00"
                @buffer.slice! 0..1

                EM.next_tick { finish! }
              else
                raise WebSocketProtocolError, "Incorrect finish frame length: #{@buffer[1].inspect}"
              end
            end
          else
            raise WebSocketProtocolError, "Unknown frame type: #{@buffer[0].inspect}"
          end
        end
      else
        @frame_state ||= :opcode

        if @frame_state == :opcode
          return unless @buffer.length >= 2

          bytes = @buffer.slice!(0...2).unpack("C*")

          @opcode = bytes[0] & 0x0f
          @fin = (bytes[0] & 0x80) != 0
          @payload_length = bytes[1] & 0x7f
          @masked = (bytes[1] & 0x80) != 0

          return error! "Received unmasked data" unless @masked

          if @payload_length == 126
            @frame_state = :payload_2
          elsif @payload_length == 127
            @frame_state = :payload_8
          else
            @frame_state = :payload
          end

        elsif @frame_state == :payload_2
          return unless @buffer.length >= 2

          @payload_length = @buffer.slice!(0...2).unpack("n")[0]

          @frame_state = :mask

        elsif @frame_state == :payload_8
          return unless @buffer.length >= 8

          (high, low) = @buffer.slice!(0...8).unpack("NN")
          @payload_length = high * (2 ** 32) + low

          @frame_state = :mask

        elsif @frame_state == :mask
          return unless @buffer.length >= 4

          bytes = @buffer[(offset)...(offset += 4)]
          @mask_key = bytes.unpack("C*")

          @frame_state = :payload

        elsif @frame_state == :payload
          return unless @buffer.length >= @payload_length

          payload = @buffer.slice!(0...@payload_length)
          payload = mask(payload, @mask_key)

          if @opcode == OPCODE_TEXT
            message = payload.force_encoding("UTF-8") if payload.respond_to? :force_encoding
            EM.next_tick { receive_message payload }
          elsif @opcode == OPCODE_CLOSE
            EM.next_tick { finish! }
          else
            error! "Unsupported opcode: %d" % @opcode
          end

          @frame_state = nil
          @opcode = @fin = @payload_length = @masked = nil
        end
      end
    rescue
      error! "Error while processing WebSocket frames"
    end

    def receive_message message
      EM.next_tick { callback :on_message, self, message rescue error! "Error in message callback" }
    end

    # This is for post-hixie-76 versions only
    def send_frame opcode, payload="", masked=false
      payload = payload.dup.force_encoding("ASCII-8BIT") if payload.respond_to? :force_encoding
      payload_length = payload.bytesize

      # We don't support continuations (yet), so always send fin
      fin_byte = 0x80
      send_data [fin_byte | opcode].pack("C")

      # We shouldn't be sending mask, we're a server only
      masked_byte = masked ? 0x80 : 0x00

      if payload_length <= 125
        send_data [masked_byte | payload_length].pack("C")

      elsif payload_length < 2 ** 16
        send_data [masked_byte | 126].pack("C")
        send_data [payload_length].pack("n")

      else
        send_data [masked_byte | 127].pack("C")
        send_data [payload_length / (2 ** 32), payload_length % (2 ** 32)].pack("NN")
      end

      if payload_length
        if masked
          mask_key = Array.new(4) { rand(256) }.pack("C*")
          send_data mask_key
          payload = mask payload, mask_key
        end

        send_data payload
      end
    end

    def send_message message
      if hixie_75? or hixie_76?
        send_data "\x00#{message}\xff"
      else
        send_frame OPCODE_TEXT, message
      end
    end

    # Finish the connection read for closing
    def finish!
      if hixie_75? or hixie_76?
        send_data "\xff\x00"
      else
        send_frame OPCODE_CLOSE
      end

      EM.next_tick { callback(:on_finish, self) rescue error! "Error in finish callback" }
      EM.next_tick { close_connection_after_writing }

      @state = :finished
    rescue
      error! "Error finishing WebSocket connection"
    end

    # Make sure we call the on_close callbacks when the connection
    # disappears
    def unbind
      EM.next_tick { callback(:on_close, self) rescue error! "Error in close callback" }
      @state = :closed
    rescue
      error! "Error closing WebSocket connection"
    end

    def error! message=nil, callback=true
      log message unless message.nil?
      log_error # Logs the exception itself

      # Allow error messages to be handled, maybe
      # but only if this error was not caused by the error callback
      if callback
        EM.next_tick { callback(:on_error, self) rescue error! "Error in error callback", true }
      end

      # Try to finish and close nicely.
      EM.next_tick { finish! } unless [:finished, :closed, :error].include? @state

      # We're closed!
      @state = :error
    end
  end

  CONNECTION = 'HTTP_CONNECTION'.freeze
  UPGRADE = 'HTTP_UPGRADE'.freeze
  SKINNY_WEBSOCKET = 'skinny.websocket'.freeze

  UPGRADE_REGEXP = /\bupgrade\b/i.freeze
  WEBSOCKET_REGEXP = /\bwebsocket\b/i.freeze

  module Helpers
    def websocket?
      env[CONNECTION] =~ UPGRADE_REGEXP && env[UPGRADE] =~ WEBSOCKET_REGEXP
    end

    def websocket options={}, &block
      env[SKINNY_WEBSOCKET] ||= begin
        raise RuntimerError, "Not a WebSocket request" unless websocket?
        options[:on_message] = block if block_given?
        Websocket.from_env(env, options)
      end
    end

    def websocket! options={}, &block
      websocket(options, &block).start!
    end
  end
end
