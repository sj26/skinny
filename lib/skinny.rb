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
    
    # Create a new WebSocket from a Thin::Request environment
    def self.from_env env, options={}
      # Pull the connection out of the env
      thin_connection = env[Thin::Request::ASYNC_CALLBACK].receiver
      # Steal the IO
      io = thin_connection.detach
      # We have all the events now, muahaha
      EM.attach(io, self, env, options)
    end
    
    def initialize env, options={}
      @env = env.dup
      @buffer = ''
      
      self.protocol = options.delete :protocol if options.has_key? :protocol
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

      # Pull out the details we care about
      @origin ||= @env['HTTP_ORIGIN']
      @location ||= "ws#{secure? ? 's' : ''}://#{@env['HTTP_HOST']}#{@env['REQUEST_PATH']}"
      @protocol ||= @env['HTTP_SEC_WEBSOCKET_PROTOCOL']
    
      EM.next_tick { callback :on_start, self rescue error! "Error in start callback" }
    
      # Queue up the actual handshake
      EM.next_tick method :handshake!
      
      @state = :started
    
      # Return self so we can be used as a response
      self
    rescue
      error! "Error starting connection"
    end
    
    attr_reader :env
    attr_accessor :origin, :location, :protocol
  
    def secure?
      @env['HTTPS'] == 'on' or
      @env['HTTP_X_FORWARDED_PROTO'] == 'https' or
      @env['rack.url_scheme'] == 'https'
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
      [key1, key2].pack("N*") + key3
    end
  
    def challenge_response
      Digest::MD5.digest(challenge)
    end
  
    # Generate the handshake
    def handshake
      "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" +
      "Connection: Upgrade\r\n" +
      "Upgrade: WebSocket\r\n" +
      "Sec-WebSocket-Location: #{location}\r\n" +
      "Sec-WebSocket-Origin: #{origin}\r\n" +
      (protocol ? "Sec-WebSocket-Protocol: #{protocol}\r\n" : "") +
      "\r\n" +
      "#{challenge_response}"
    end
    
    def handshake!
      [key1, key2].each { |key| raise WebSocketProtocolError, "Invalid key: #{key}" if key >= 2**32 }
      
      # XXX: Should we wait for 8 bytes?
      raise WebSocketProtocolError, "Invalid challenge: #{key3}" if key3.length < 8
      
      send_data handshake
      @state = :handshook
    
      EM.next_tick { callback :on_handshake, self rescue error! "Error in handshake callback" }
    rescue
      error! "Error during WebSocket connection handshake"
    end
    
    def receive_data data
      @buffer += data
    
      EM.next_tick { process_frame } if @state == :handshook
    rescue
      error! "Error while receiving WebSocket data"
    end
    
    def process_frame
      if @buffer.length >= 1
        if @buffer[0] == "\x00"
          if ending = @buffer.index("\xff")
            frame = @buffer.slice! 0..ending
            message = frame[1..-2]
          
            EM.next_tick { receive_message message }
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
    rescue
      error! "Error while processing WebSocket frames"
    end
  
    def receive_message message
      EM.next_tick { callback :on_message, self, message rescue error! "Error in message callback" }
    end
  
    def frame_message message
      "\x00#{message}\xff"
    end
  
    def send_message message
      send_data frame_message(message)
    end
  
    # Finish the connection read for closing
    def finish!
      send_data "\xff\x00"
    
      EM.next_tick { callback :on_finish, self rescue error! "Error in finish callback" }
      EM.next_tick { close_connection_after_writing }

      @state = :finished
    rescue
      error! "Error finishing WebSocket connection"
    end
    
    # Make sure we call the on_close callbacks when the connection
    # disappears
    def unbind
      EM.next_tick { callback :on_close, self rescue error! "Error in close callback" }
      @state = :closed
    rescue
      error! "Error closing WebSocket connection"
    end
    
    def error! message=nil
      log message unless message.nil?
      log_error
      
      # Allow error messages to be handled, maybe
      EM.next_tick { callback :on_error, self rescue error! "Error in error callback" }
      
      # Try to finish and close nicely.
      EM.next_tick { finish! } unless [:finished, :closed, :error].include? @state

      @state = :error
    end
  end

  module Helpers
    def websocket?
      env['HTTP_CONNECTION'] == 'Upgrade' && env['HTTP_UPGRADE'] == 'WebSocket'
    end
  
    def websocket(options={}, &block)
      env['skinny.websocket'] ||= begin
        raise RuntimerError, "Not a WebSocket request" unless websocket?
        options[:on_message] = block if block_given?
        Websocket.from_env(env, options)
      end
    end
  
    def websocket!(options={}, &block)
      websocket(options, &block).start!
    end
  end
end