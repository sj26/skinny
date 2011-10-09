# Skinny

Simple, upgradable Thin WebSockets.

I wanted to be able to upgrade a plain old Rack request to a proper
WebSocket. The easiest way seemed to use the oh-so-nice-and-clean
[Thin][thin] with a new pair of skinnies.

More details coming soon.

## Examples

More comprehensive examples will be coming soon. Here's a really
simple, not-yet-optimised example I'm using at the moment:

    class Sinatra::Request
      include Skinny::Helpers
    end

    module MailCatcher
      class Web < Sinatra::Base
        get '/messages' do
          if request.websocket?
            request.websocket! :protocol => "MailCatcher 0.2 Message Push",
              :on_start => proc do |websocket|
                subscription = MailCatcher::Events::MessageAdded.subscribe { |message| websocket.send_message message.to_json }
                websocket.on_close do |websocket|
                  MailCatcher::Events::MessageAdded.unsubscribe subscription
                end
              end
          else
            MailCatcher::Mail.messages.to_json
          end
        end
      end
    end

This syntax will probably get cleaned up. I would like to build a
nice Sinatra handler with DSL with unbound handlers so Sinatra
requests can be recycled.

## TODO

 * Nicer
 * Documentation
 * Tests
 * Make more generic for alternate server implementations?

## Thanks

The latest WebSocket draft support is adapted from https://github.com/gimite/web-socket-ruby -- thank you!

## Copyright

Copyright (c) 2010 Samuel Cochran. See LICENSE for details.

## Wear Them

[Do you?][jeans]

[thin]: http://code.macournoyer.com/thin/
[jeans]: http://www.shaunoakes.com/images/skinny-jeans-no.jpg