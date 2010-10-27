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

  class Websocket < EventMachine::Connection
    include Callbacks
  
    define_callback :on_open, :on_start, :on_handshake, :on_message, :on_error, :on_finish, :on_close

    # 4mb is almost too generous, imho.
    MAX_BUFFER_LENGTH = 2 ** 32
  
    def self.from_env env, options={}
      # Steal the connection
      thin_connection = env[Thin::Request::ASYNC_CALLBACK].receiver
      # We have all the events now, muahaha
      EM.attach(thin_connection.detach, self, env, options)
    end
  
    def initialize env, options={}
      @env = env.dup
      @buffer = ''
      
      self.protocol = options.delete :protocol if options.has_key? :protocol
      [:on_open, :on_start, :on_handshake, :on_message, :on_error, :on_finish, :on_close].each do |name|
        send name, &options.delete(name) if options.has_key?(name)
      end
      raise ArgumentError, "Unknown options: #{options.inspect}" unless options.empty?
      
      EM.next_tick { callback :on_open, self }
    end
  
    # Return an async response -- stops Thin doing anything with connection.
    def response
      Thin::Connection::AsyncResponse
    end
  
    # Arrayify self into a response tuple
    alias :to_a :response

    def start!
      # Steal any remaining data from rack.input
      @buffer = @env[Thin::Request::RACK_INPUT].read + @buffer
    
      # Remove references to Thin connection objects, freeing memory
      @env.delete Thin::Request::RACK_INPUT
      @env.delete Thin::Request::ASYNC_CALLBACK
      @env.delete Thin::Request::ASYNC_CLOSE
    
      EM.next_tick { callback :on_start, self }
    
      # Queue up the actual handshake
      EM.next_tick method :handshake!
    
      # Return self so we can be used as a response
      self
    rescue
      error! $!
    end
  
    def protocol
      @env['HTTP_SEC_WEBSOCKET_PROTOCOL']
    end
  
    def protocol= value
      @env['HTTP_SEC_WEBSOCKET_PROTOCOL'] = value
    end
  
    [1, 2].each do |i|
      define_method "key#{i}" do
        key = @env["HTTP_SEC_WEBSOCKET_KEY#{i}"]
        key.scan(/[0-9]/).join.to_i / key.count(' ')
      end
    end
  
    def key3
      @key3 ||= @buffer.slice!(0...8)
    end
  
    def challenge?
      @env.has_key? 'HTTP_SEC_WEBSOCKET_KEY1'
    end
  
    def challenge
      [key1, key2].pack("N*") + key3
    end
  
    def challenge_response
      Digest::MD5.digest(challenge)
    end
  
    def handshake
      "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" +
      "Connection: Upgrade\r\n" +
      "Upgrade: WebSocket\r\n" +
      "Sec-WebSocket-Location: ws#{@env['rack.url_scheme'] == 'https' ? 's' : ''}://#{@env['HTTP_HOST']}#{@env['REQUEST_PATH']}\r\n" +
      "Sec-WebSocket-Origin: #{@env['HTTP_ORIGIN']}\r\n" +
      ("Sec-WebSocket-Protocol: #{@env['HTTP_SEC_WEBSOCKET_PROTOCOL']}\r\n" if @env['HTTP_SEC_WEBSOCKET_PROTOCOL']) +
      "\r\n" +
      "#{challenge_response}"
    end
  
    def handshake!
      [key1, key2].each { |key| raise WebSocketProtocolError, "Invalid key: #{key}" if key >= 2**32 }
      # XXX: Should we wait for 8 bytes?
      raise WebSocketProtocolError, "Invalid challenge: #{key3}" if key3.length < 8
      
      send_data handshake
      @handshook = true
    
      EM.next_tick { callback :on_handshake, self }
    rescue
      error! $!
    end
  
    def receive_data data
      @buffer += data
    
      EM.next_tick { process_frame } if @handshook
    rescue
      error! $!
    end
  
    def process_frame
      if @buffer.length >= 1
        if @buffer[0] == "\x00"
          if ending = @buffer.index("\xff")
            frame = @buffer.slice! 0..ending
            message = frame[1..-2]
          
            EM.next_tick { receive_message message }
          elsif @buffer.length > MAX_BUFFER_LENGTH
            error! "Maximum buffer length (#{MAX_BUFFER_LENGTH}) exceeded: #{@buffer.length}"
          end
        elsif @buffer[0] == "\xff"
          if @buffer.length > 1
            if @buffer[1] == "\x00"
              @buffer.slice! 0..1
        
              EM.next_tick { finish! }
            else
              error! "Incorrect finish frame length: #{@buffer[1].inspect}"
            end
          end
        else
          error! "Unknown frame type: #{@buffer[0].inspect}"
        end
      end
    end
  
    def receive_message message
      EM.next_tick { callback :on_message, self, message }
    end
  
    def frame_message message
      "\x00#{message}\xff"
    end
  
    def send_message message
      send_data frame_message(message)
    end
  
    def error! message=nil
      EM.next_tick { callback :on_error, self }
      EM.next_tick { finish! } unless @finished
      # XXX: Log or something
      puts "Websocket Error: #{$!}"
    end
  
    def finish!
      send_data "\xff\x00"
      close_connection_after_writing
      @finished = true
    
      EM.next_tick { callback :on_finish, self }
    rescue
      error! $!
    end
  
    def unbind
      EM.next_tick { callback :on_close, self }
    end
  end

  module RequestHelpers
    def websocket?
      @env['HTTP_CONNECTION'] == 'Upgrade' && @env['HTTP_UPGRADE'] == 'WebSocket'
    end
  
    def websocket(options={})
      @env['skinny.websocket'] ||= begin
        raise RuntimerError, "Not a WebSocket request" unless websocket?
        Websocket.from_env(@env, options)
      end
    end
  
    def websocket!(options={})
      websocket(options).start!
    end
  end
end