# Rack entry point for Render and other platforms.
# Start with: bundle exec rackup -s puma -o 0.0.0.0 -p $PORT
require_relative 'web'
run Sinatra::Application
