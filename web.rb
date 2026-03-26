# Prevent Sinatra from parsing command-line arguments that might cause issues
# We'll configure the port and bind address directly in code
ARGV.clear if ARGV.any?

require 'sinatra'
require 'stripe'
require 'dotenv'
require 'json'
require 'sinatra/cross_origin'
require 'rack/protection'
require 'net/http'
require 'uri'

# Set the port from environment variable or default to 4567
# This ensures compatibility with Railway, Render, Heroku, and other platforms
set :port, ENV['PORT'] ? ENV['PORT'].to_i : 4567
set :bind, '0.0.0.0'

# Load environment variables
# Load .env file if it exists (for local development)
Dotenv.load if File.exist?('.env')

# ─────────────────────────────────────────────────────────────────────────────
# FIREBASE REALTIME DATABASE (logs)
# URL = your Realtime Database host (correct for project stripe-backend-ed4ed).
# SECRET = legacy Database secret from Firebase Console → ⚙ Project settings →
#          Service accounts → Database secrets — NOT the project id (stripe-backend-ed4ed).
#          https://console.firebase.google.com/project/stripe-backend-ed4ed/settings/serviceaccounts/databasesecrets
# Leave FIREBASE_DB_SECRET empty to disable Firebase logging (console logs still run).
# ─────────────────────────────────────────────────────────────────────────────
FIREBASE_DB_URL    = 'https://stripe-backend-ed4ed-default-rtdb.firebaseio.com'.freeze
FIREBASE_DB_SECRET = ''.freeze # paste your Database secret string here
FIREBASE_ENABLED   = !FIREBASE_DB_SECRET.nil? && !FIREBASE_DB_SECRET.strip.empty?

# Production/Environment Configuration
PRODUCTION = ENV['RACK_ENV'] == 'production' || ENV['ENVIRONMENT'] == 'production'
STRIPE_ENV = ENV['STRIPE_ENV'] || (PRODUCTION ? 'production' : 'test')

# Stripe Configuration
if STRIPE_ENV == 'production'
  Stripe.api_key = ENV['STRIPE_SECRET_KEY'] || ENV['STRIPE_LIVE_SECRET_KEY']
else
  Stripe.api_key = ENV['STRIPE_TEST_SECRET_KEY']
end
Stripe.api_version = '2024-09-30.acacia'

# The Stripe Connect account this backend operates on behalf of (direct charges).
# Set STRIPE_CONNECTED_ACCOUNT_ID in your environment / .env file.
CONNECTED_ACCOUNT_ID = (ENV['STRIPE_CONNECTED_ACCOUNT_ID'] || 'acct_1T5aDBBfHXwLiSAu').freeze

if CONNECTED_ACCOUNT_ID.nil? || CONNECTED_ACCOUNT_ID.strip.empty?
  raise "FATAL: STRIPE_CONNECTED_ACCOUNT_ID environment variable is not set."
end

def connected_account_request_opts
  { stripe_account: CONNECTED_ACCOUNT_ID }
end

# Production Configuration Validation
if PRODUCTION
  if Stripe.api_key.nil? || Stripe.api_key.empty? || !Stripe.api_key.start_with?('sk_live')
    puts "\n⚠️  WARNING: STRIPE_SECRET_KEY should be set to your live key (sk_live_...) in production!\n\n"
  end
end

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

LOG_SEP = ('─' * 72).freeze

def ts
  Time.now.strftime('%Y-%m-%d %H:%M:%S.%L')
end

# Push a log payload to Firebase Realtime Database asynchronously.
# Runs in a background thread so it never blocks request handling.
# Silently skips if Firebase secret is not configured.
def firebase_log(payload)
  return unless FIREBASE_ENABLED
  Thread.new do
    begin
      uri = URI("#{FIREBASE_DB_URL}/logs.json")
      uri.query = URI.encode_www_form('auth' => FIREBASE_DB_SECRET)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 3
      http.read_timeout = 5
      req = Net::HTTP::Post.new(uri.request_uri, 'Content-Type' => 'application/json')
      req.body = payload.merge(
        ts:  Time.now.utc.iso8601(3),
        env: defined?(STRIPE_ENV) ? STRIPE_ENV : 'unknown'
      ).to_json
      http.request(req)
    rescue => _e
      # intentionally silent — Firebase logging must never crash the main app
    end
  end
end

def log_section(title)
  puts "\n#{LOG_SEP}"
  puts "  #{ts}  #{title}"
  puts LOG_SEP
  firebase_log(level: 'section', message: title)
end

def log_info(message)
  puts "[#{ts}] #{message}"
  firebase_log(level: 'info', message: message)
  return message
end

def log_kv(label, hash)
  return if hash.nil? || (hash.respond_to?(:empty?) && hash.empty?)
  puts "[#{ts}] #{label}:"
  hash.each { |k, v| puts "            #{k}: #{v}" }
  firebase_log(level: 'kv', label: label, data: hash)
end

def log_stripe_request(endpoint, stripe_method, stripe_params, request_opts)
  puts "[#{ts}] >>> STRIPE API CALL  [#{endpoint}]"
  puts "            Method : #{stripe_method}"
  puts "            Params : #{stripe_params.to_json rescue stripe_params.inspect}"
  puts "            Opts   : #{request_opts.inspect}"
  firebase_log(
    level:    'stripe_request',
    endpoint: endpoint,
    method:   stripe_method.to_s,
    params:   (stripe_params.to_json rescue stripe_params.inspect),
    opts:     request_opts.inspect
  )
end

def log_stripe_response(endpoint, object_type, response)
  puts "[#{ts}] <<< STRIPE RESPONSE  [#{endpoint}]"
  puts "            Type   : #{object_type}"
  begin
    puts "            JSON   : #{response.to_hash.to_json rescue response.inspect}"
  rescue => ex
    puts "            (could not serialize response: #{ex.message})"
  end
  response_json = begin
    response.to_hash.to_json
  rescue
    response.inspect
  end
  firebase_log(
    level:    'stripe_response',
    endpoint: endpoint,
    type:     object_type.to_s,
    response: response_json
  )
end

def log_connect_context(endpoint, step = nil)
  msg = "[#{ts}] [#{endpoint}] stripe_account=#{CONNECTED_ACCOUNT_ID}"
  msg += " | #{step}" if step
  puts msg
  firebase_log(level: 'connect', endpoint: endpoint, step: step, stripe_account: CONNECTED_ACCOUNT_ID)
end

def log_error(endpoint, message, exception = nil)
  puts "[#{ts}] *** ERROR  [#{endpoint}]: #{message}"
  if exception
    puts "            Class  : #{exception.class}"
    puts "            Msg    : #{exception.message}"
    if exception.respond_to?(:http_status)
      puts "            HTTP   : #{exception.http_status}"
    end
    if exception.respond_to?(:code)
      puts "            Code   : #{exception.code}"
    end
    if exception.respond_to?(:error)
      err = exception.error rescue nil
      puts "            Error  : #{err.inspect}" if err
    end
    if exception.respond_to?(:json_body)
      puts "            Body   : #{exception.json_body.to_json rescue exception.json_body.inspect}"
    end
    puts "            Trace  : #{exception.backtrace&.first(5)&.join(' | ')}"
  end
  full = "[#{endpoint}] Error: #{message}"
  full += " | #{exception.class} - #{exception.message}" if exception
  ex_payload = if exception
    {
      class:       exception.class.to_s,
      message:     exception.message,
      http_status: (exception.http_status rescue nil),
      code:        (exception.code rescue nil),
      body:        (exception.json_body.to_json rescue nil),
      trace:       exception.backtrace&.first(5)&.join(' | ')
    }.compact
  end
  firebase_log(
    level:     'error',
    endpoint:  endpoint,
    message:   message,
    exception: ex_payload
  )
  return full
end

# ─────────────────────────────────────────────────────────────────────────────
# STARTUP BANNER
# ─────────────────────────────────────────────────────────────────────────────

puts "\n#{LOG_SEP}"
puts "  CARWASH STRIPE TERMINAL BACKEND  —  #{ts}"
puts LOG_SEP
puts "  STRIPE_ENV         : #{STRIPE_ENV}"
puts "  PRODUCTION         : #{PRODUCTION}"
puts "  Stripe API version : #{Stripe.api_version}"
puts "  Connected account  : #{CONNECTED_ACCOUNT_ID}"
key = Stripe.api_key.to_s
puts "  API key (masked)   : #{key.empty? ? '(none)' : key[0..6] + '...' + key[-4..]}"
puts "  Firebase logging   : #{FIREBASE_ENABLED ? "ENABLED  (#{FIREBASE_DB_URL}/logs)" : 'DISABLED (paste FIREBASE_DB_SECRET in web.rb to enable)'}"
puts LOG_SEP + "\n\n"

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY / CORS
# ─────────────────────────────────────────────────────────────────────────────

configure do
  enable :cross_origin
  enable :sessions
  set :protection, :except => [:json_csrf]
end

before do
  response.headers['Access-Control-Allow-Origin'] = '*'
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept'
  response.headers['Access-Control-Max-Age'] = '3600'
  response.headers['X-Content-Type-Options'] = 'nosniff'
  response.headers['X-Frame-Options'] = 'DENY'
  response.headers['X-XSS-Protection'] = '1; mode=block'
  if PRODUCTION
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
  end

  # ── Log every incoming HTTP request ──────────────────────────────────────
  unless request.request_method == 'OPTIONS'
    log_section("INCOMING REQUEST  #{request.request_method} #{request.path_info}")
    puts "[#{ts}] Remote IP    : #{request.ip}"
    puts "[#{ts}] Content-Type : #{request.content_type}"
    puts "[#{ts}] User-Agent   : #{request.user_agent}"

    # Re-read body safely (Sinatra may have already consumed it)
    raw = nil
    begin
      request.body.rewind
      raw = request.body.read
      request.body.rewind
    rescue => ex
      raw = "(could not read body: #{ex.message})"
    end
    puts "[#{ts}] Raw body     : #{raw.to_s.empty? ? '(empty)' : raw}"

    unless params.empty?
      puts "[#{ts}] Parsed params:"
      params.each { |k, v| puts "            #{k}: #{v.inspect}" }
    end
  end
end

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token"
  response.headers["Access-Control-Allow-Origin"] = "*"
  status 200
end

# ─────────────────────────────────────────────────────────────────────────────
# API KEY VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def validateApiKey
  puts "[#{ts}] [validateApiKey] STRIPE_ENV=#{STRIPE_ENV} | key_present=#{!Stripe.api_key.to_s.empty?}"
  if Stripe.api_key.nil? || Stripe.api_key.empty?
    mode = STRIPE_ENV == 'production' ? 'production' : 'test'
    return "Error: you provided an empty secret key. Please provide your #{mode} mode secret key."
  end
  if Stripe.api_key.start_with?('pk')
    return "Error: you used a publishable key. Please use your secret key."
  end
  if STRIPE_ENV == 'production'
    unless Stripe.api_key.start_with?('sk_live')
      return "Error: production mode requires a live key (sk_live_...)."
    end
  else
    if Stripe.api_key.start_with?('sk_live')
      return "Error: test mode is active but a live key was supplied."
    end
    unless Stripe.api_key.start_with?('sk_test')
      return "Error: invalid secret key format. Expected sk_test_..."
    end
  end
  puts "[#{ts}] [validateApiKey] OK"
  return nil
end

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH / ROOT
# ─────────────────────────────────────────────────────────────────────────────

get '/' do
  status 404
  content_type :json
  {:error => 'Not Found', :message => 'This service is not available.'}.to_json
end

get '/health' do
  log_section("GET /health")
  payload = {
    :status            => 'ok',
    :stripe_env        => STRIPE_ENV,
    :api_version       => Stripe.api_version,
    :connected_account => CONNECTED_ACCOUNT_ID,
  }
  puts "[#{ts}] Health response: #{payload.to_json}"
  status 200
  content_type :json
  payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /register_reader
# ─────────────────────────────────────────────────────────────────────────────

post '/register_reader' do
  log_section("POST /register_reader")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /register_reader", validationError)
  end

  log_connect_context("POST /register_reader", "registering reader on connected account")

  reader_params = {
    :registration_code => params[:registration_code],
    :label             => params[:label],
    :location          => params[:location],
  }

  puts "[#{ts}] Input params received:"
  puts "            registration_code : #{params[:registration_code].inspect}"
  puts "            label             : #{params[:label].inspect}"
  puts "            location          : #{params[:location].inspect}"

  begin
    log_stripe_request("POST /register_reader", "Stripe::Terminal::Reader.create", reader_params, connected_account_request_opts)
    reader = Stripe::Terminal::Reader.create(reader_params, connected_account_request_opts)
    log_stripe_response("POST /register_reader", "Terminal::Reader", reader)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /register_reader", "Failed to register reader", e)
  end

  puts "[#{ts}] SUCCESS  reader_id=#{reader.id} | account=#{CONNECTED_ACCOUNT_ID}"
  status 200
  return reader.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /connection_token
# ─────────────────────────────────────────────────────────────────────────────

post '/connection_token' do
  log_section("POST /connection_token")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /connection_token", validationError)
  end

  location_id = params[:location] || params['location_id']
  puts "[#{ts}] Input params received:"
  puts "            location (param :location)   : #{params[:location].inspect}"
  puts "            location_id (param key)       : #{params['location_id'].inspect}"
  puts "            resolved location_id          : #{location_id.inspect}"

  log_connect_context("POST /connection_token", "creating ConnectionToken on connected account")

  token_params = {}
  if location_id && !location_id.to_s.strip.empty?
    token_params[:location] = location_id.strip
    puts "[#{ts}] Location scoping ENABLED: #{token_params[:location]}"
  else
    puts "[#{ts}] Location scoping NOT set — token valid for ALL readers on account"
  end

  begin
    log_stripe_request("POST /connection_token", "Stripe::Terminal::ConnectionToken.create", token_params, connected_account_request_opts)
    token = Stripe::Terminal::ConnectionToken.create(token_params, connected_account_request_opts)
    puts "[#{ts}] <<< STRIPE RESPONSE  [POST /connection_token]"
    puts "            Type   : Terminal::ConnectionToken"
    puts "            secret : #{token.secret[0..8]}... (truncated for security)"
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /connection_token", "Failed to create ConnectionToken", e)
  end

  response_payload = {:secret => token.secret}
  puts "[#{ts}] SUCCESS  account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: { secret: '#{token.secret[0..8]}...' }"
  content_type :json
  status 200
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Look up or create a Customer on the connected account
# ─────────────────────────────────────────────────────────────────────────────

def lookupOrCreateCustomerOnConnectedAccount(customerEmail, customer_name = nil)
  request_opts = connected_account_request_opts
  email = customerEmail.to_s.strip
  email = nil if email.empty?
  name  = customer_name.to_s.strip
  name  = nil if name.empty?

  puts "[#{ts}] [Customer] Input  email=#{email.inspect} | name=#{name.inspect} | account=#{CONNECTED_ACCOUNT_ID}"

  begin
    if email
      list_params = { email: email, limit: 1 }
      log_stripe_request("Customer.list", "Stripe::Customer.list", list_params, request_opts)
      customerList = Stripe::Customer.list(list_params, request_opts).data
      puts "[#{ts}] [Customer.list] <<< found #{customerList.size} customer(s) matching email=#{email}"

      if customerList.length >= 1
        cid = customerList[0].id
        puts "[#{ts}] [Customer] Existing customer found: #{cid}"
        if name
          update_params = { name: name }
          log_stripe_request("Customer.update", "Stripe::Customer.update", update_params, request_opts)
          Stripe::Customer.update(cid, update_params, request_opts)
          puts "[#{ts}] [Customer.update] <<< name updated to '#{name}' on #{cid}"
        end
        return cid
      end

      create_params = { email: email }
      create_params[:name] = name if name
      log_stripe_request("Customer.create", "Stripe::Customer.create", create_params, request_opts)
      newCustomer = Stripe::Customer.create(create_params, request_opts)
      puts "[#{ts}] [Customer.create] <<< new customer id=#{newCustomer.id} | email=#{email} | name=#{name.inspect}"
      return newCustomer.id
    else
      create_params = { email: "walk-in@terminal.local", metadata: { source: "terminal_walkin" } }
      create_params[:name] = name if name
      log_stripe_request("Customer.create (walk-in)", "Stripe::Customer.create", create_params, request_opts)
      newCustomer = Stripe::Customer.create(create_params, request_opts)
      puts "[#{ts}] [Customer.create walk-in] <<< id=#{newCustomer.id} | name=#{name.inspect}"
      return newCustomer.id
    end
  rescue Stripe::StripeError => e
    log_error("lookupOrCreateCustomerOnConnectedAccount", "Creating or retrieving customer", e)
    raise
  end
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /create_payment_intent
# ─────────────────────────────────────────────────────────────────────────────

post '/create_payment_intent' do
  log_section("POST /create_payment_intent")

  # Full raw dump first
  begin
    request.body.rewind
    raw_body = request.body.read
    request.body.rewind
  rescue => ex
    raw_body = "(could not read: #{ex.message})"
  end

  puts "[#{ts}] All params keys : #{params.keys.inspect}"
  puts "[#{ts}] Full params     : #{params.inspect}"
  puts "[#{ts}] Raw body        : #{raw_body}"
  puts "[#{ts}] Individual params:"
  puts "            amount               : #{params[:amount].inspect}"
  puts "            currency             : #{params[:currency].inspect}"
  puts "            description          : #{params[:description].inspect}"
  puts "            email                : #{params[:email].inspect}"
  puts "            receipt_email        : #{params[:receipt_email].inspect}"
  puts "            customer_name        : #{(params[:customer_name] || params['customer_name']).inspect}"
  puts "            name                 : #{(params[:name] || params['name']).inspect}"
  puts "            payment_method_types : #{params[:payment_method_types].inspect}"
  puts "            capture_method       : #{params[:capture_method].inspect}"
  puts "            payment_method_opts  : #{params[:payment_method_options].inspect}"
  puts "            setup_future_usage   : #{params[:setup_future_usage].inspect}"
  puts "            metadata             : #{params[:metadata].inspect}"
  puts "            location_id          : #{(params[:location_id] || params['location_id']).inspect}"
  puts "            order_id             : #{(params[:order_id] || params['order_id']).inspect}"
  puts "            tags                 : #{(params[:tags] || params['tags']).inspect}"

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_payment_intent", validationError)
  end

  log_connect_context("POST /create_payment_intent", "creating PaymentIntent on connected account")

  begin
    customer_email = params[:email] || params[:receipt_email]
    customer_name  = params[:customer_name] || params[:name] || params['customer_name'] || params['name']

    puts "[#{ts}] Resolved customer_email=#{customer_email.inspect} | customer_name=#{customer_name.inspect}"

    payment_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
      :capture_method       => params[:capture_method] || 'manual',
      :amount               => params[:amount],
      :currency             => params[:currency] || 'usd',
      :description          => params[:description] || 'Example PaymentIntent',
      :payment_method_options => params[:payment_method_options] || {},
      :receipt_email        => customer_email,
    }

    if params[:setup_future_usage] == 'off_session'
      payment_intent_params[:setup_future_usage] = 'off_session'
      puts "[#{ts}] setup_future_usage=off_session SET (saving card for recurring)"
    end

    request_opts = connected_account_request_opts

    puts "[#{ts}] --- Step 1: Resolve/create customer ---"
    connected_customer_id = lookupOrCreateCustomerOnConnectedAccount(customer_email, customer_name)
    payment_intent_params[:customer] = connected_customer_id
    puts "[#{ts}] Customer resolved: #{connected_customer_id}"

    if params[:metadata] && !params[:metadata].empty?
      payment_intent_params[:metadata] = params[:metadata]
      puts "[#{ts}] Metadata attached: #{params[:metadata].inspect}"
    end

    puts "[#{ts}] --- Step 2: Create PaymentIntent ---"
    puts "[#{ts}] Final PaymentIntent params being sent to Stripe:"
    payment_intent_params.each { |k, v| puts "            #{k}: #{v.inspect}" }
    puts "[#{ts}] Request opts (Stripe-Account header): #{request_opts.inspect}"

    log_stripe_request("POST /create_payment_intent", "Stripe::PaymentIntent.create", payment_intent_params, request_opts)
    payment_intent = Stripe::PaymentIntent.create(payment_intent_params, request_opts)
    log_stripe_response("POST /create_payment_intent", "PaymentIntent (created)", payment_intent)

    puts "[#{ts}] --- Step 3: Update description to PI id ---"
    update_params = { description: payment_intent.id }
    log_stripe_request("POST /create_payment_intent (update)", "Stripe::PaymentIntent.update", update_params, request_opts)
    payment_intent = Stripe::PaymentIntent.update(payment_intent.id, update_params, request_opts)
    log_stripe_response("POST /create_payment_intent", "PaymentIntent (updated)", payment_intent)

  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_payment_intent", "Failed to create PaymentIntent", e)
  end

  response_payload = { :intent => payment_intent.id, :secret => payment_intent.client_secret }
  puts "[#{ts}] SUCCESS  payment_intent_id=#{payment_intent.id} | status=#{payment_intent.status} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /capture_payment_intent
# ─────────────────────────────────────────────────────────────────────────────

post '/capture_payment_intent' do
  log_section("POST /capture_payment_intent")

  id              = params["payment_intent_id"]
  amount_override = params["amount_to_capture"]

  puts "[#{ts}] Input params received:"
  puts "            payment_intent_id : #{id.inspect}"
  puts "            amount_to_capture : #{amount_override.inspect}"

  log_connect_context("POST /capture_payment_intent", "capturing PaymentIntent on connected account")

  begin
    request_opts = connected_account_request_opts

    if !amount_override.nil?
      capture_params = { amount_to_capture: amount_override }
      log_stripe_request("POST /capture_payment_intent", "Stripe::PaymentIntent.capture(#{id})", capture_params, request_opts)
      payment_intent = Stripe::PaymentIntent.capture(id, capture_params, request_opts)
    else
      log_stripe_request("POST /capture_payment_intent", "Stripe::PaymentIntent.capture(#{id})", {}, request_opts)
      payment_intent = Stripe::PaymentIntent.capture(id, {}, request_opts)
    end

    log_stripe_response("POST /capture_payment_intent", "PaymentIntent (captured)", payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /capture_payment_intent", "Failed to capture PaymentIntent", e)
  end

  response_payload = { :intent => payment_intent.id, :secret => payment_intent.client_secret }
  puts "[#{ts}] SUCCESS  payment_intent_id=#{id} | new_status=#{payment_intent.status} | amount_captured=#{payment_intent.amount_received rescue 'n/a'} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /cancel_payment_intent
# ─────────────────────────────────────────────────────────────────────────────

post '/cancel_payment_intent' do
  log_section("POST /cancel_payment_intent")

  id = params["payment_intent_id"]
  puts "[#{ts}] Input params received:"
  puts "            payment_intent_id : #{id.inspect}"

  log_connect_context("POST /cancel_payment_intent", "canceling PaymentIntent on connected account")

  begin
    log_stripe_request("POST /cancel_payment_intent", "Stripe::PaymentIntent.cancel(#{id})", {}, connected_account_request_opts)
    payment_intent = Stripe::PaymentIntent.cancel(id, {}, connected_account_request_opts)
    log_stripe_response("POST /cancel_payment_intent", "PaymentIntent (canceled)", payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /cancel_payment_intent", "Failed to cancel PaymentIntent", e)
  end

  response_payload = { :intent => payment_intent.id, :secret => payment_intent.client_secret }
  puts "[#{ts}] SUCCESS  payment_intent_id=#{id} | new_status=#{payment_intent.status} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /create_setup_intent
# ─────────────────────────────────────────────────────────────────────────────

post '/create_setup_intent' do
  log_section("POST /create_setup_intent")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_setup_intent", validationError)
  end

  puts "[#{ts}] Input params received:"
  puts "            payment_method_types : #{params[:payment_method_types].inspect}"
  puts "            customer             : #{params[:customer].inspect}"
  puts "            description          : #{params[:description].inspect}"
  puts "            on_behalf_of         : #{params[:on_behalf_of].inspect}"

  log_connect_context("POST /create_setup_intent", "creating SetupIntent on connected account")

  begin
    setup_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
    }
    setup_intent_params[:customer]      = params[:customer]      if !params[:customer].nil?
    setup_intent_params[:description]   = params[:description]   if !params[:description].nil?
    setup_intent_params[:on_behalf_of]  = params[:on_behalf_of]  if !params[:on_behalf_of].nil?

    puts "[#{ts}] SetupIntent params being sent to Stripe:"
    setup_intent_params.each { |k, v| puts "            #{k}: #{v.inspect}" }
    puts "[#{ts}] Request opts: #{connected_account_request_opts.inspect}"

    log_stripe_request("POST /create_setup_intent", "Stripe::SetupIntent.create", setup_intent_params, connected_account_request_opts)
    setup_intent = Stripe::SetupIntent.create(setup_intent_params, connected_account_request_opts)
    log_stripe_response("POST /create_setup_intent", "SetupIntent", setup_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_setup_intent", "Failed to create SetupIntent", e)
  end

  response_payload = { :intent => setup_intent.id, :secret => setup_intent.client_secret }
  puts "[#{ts}] SUCCESS  setup_intent_id=#{setup_intent.id} | status=#{setup_intent.status} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Look up or create example@test.com customer (saved-card demo)
# ─────────────────────────────────────────────────────────────────────────────

def lookupOrCreateExampleCustomerOnConnectedAccount
  customerEmail = "example@test.com"
  request_opts  = connected_account_request_opts
  puts "[#{ts}] [ExampleCustomer] looking up #{customerEmail} on account=#{CONNECTED_ACCOUNT_ID}"
  begin
    list_params = { email: customerEmail, limit: 1 }
    log_stripe_request("ExampleCustomer.list", "Stripe::Customer.list", list_params, request_opts)
    customerList = Stripe::Customer.list(list_params, request_opts).data
    puts "[#{ts}] [ExampleCustomer.list] <<< #{customerList.size} result(s)"
    if customerList.length == 1
      puts "[#{ts}] [ExampleCustomer] found existing: #{customerList[0].id}"
      return customerList[0]
    else
      create_params = { email: customerEmail }
      log_stripe_request("ExampleCustomer.create", "Stripe::Customer.create", create_params, request_opts)
      customer = Stripe::Customer.create(create_params, request_opts)
      puts "[#{ts}] [ExampleCustomer.create] <<< new id=#{customer.id}"
      return customer
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("lookupOrCreateExampleCustomerOnConnectedAccount", "Creating or retrieving example customer", e)
  end
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /attach_payment_method_to_customer
# ─────────────────────────────────────────────────────────────────────────────

post '/attach_payment_method_to_customer' do
  log_section("POST /attach_payment_method_to_customer")

  payment_method_id = params[:payment_method_id]

  puts "[#{ts}] Input params received:"
  puts "            payment_method_id : #{payment_method_id.inspect}"
  puts "            customer_id       : #{params[:customer_id].inspect}"
  puts "            email             : #{params[:email].inspect}"
  puts "            receipt_email     : #{params[:receipt_email].inspect}"

  if payment_method_id.nil? || payment_method_id.to_s.strip.empty?
    status 400
    return log_error("POST /attach_payment_method_to_customer", "'payment_method_id' is required")
  end

  begin
    customer_id = params[:customer_id]
    if customer_id && !customer_id.to_s.strip.empty?
      customer_id = customer_id.strip
      puts "[#{ts}] Using provided customer_id=#{customer_id}"
    else
      customer_email = params[:email] || params[:receipt_email]
      puts "[#{ts}] No customer_id provided — resolving via email=#{customer_email.inspect}"
      customer_id = lookupOrCreateCustomerOnConnectedAccount(customer_email)
      puts "[#{ts}] Resolved customer_id=#{customer_id}"
    end

    attach_params = { customer: customer_id }
    log_stripe_request("POST /attach_payment_method_to_customer", "Stripe::PaymentMethod.attach(#{payment_method_id})", attach_params, connected_account_request_opts)
    payment_method = Stripe::PaymentMethod.attach(payment_method_id, attach_params, connected_account_request_opts)
    log_stripe_response("POST /attach_payment_method_to_customer", "PaymentMethod (attached)", payment_method)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /attach_payment_method_to_customer", "Failed to attach PaymentMethod to Customer", e)
  end

  response_payload = { :payment_method => payment_method.id, :customer => customer_id }
  puts "[#{ts}] SUCCESS  pm_id=#{payment_method_id} | customer_id=#{customer_id} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  content_type :json
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /update_payment_intent
# ─────────────────────────────────────────────────────────────────────────────

post '/update_payment_intent' do
  log_section("POST /update_payment_intent")

  payment_intent_id = params["payment_intent_id"]

  puts "[#{ts}] Input params received:"
  puts "            payment_intent_id : #{payment_intent_id.inspect}"
  puts "            receipt_email     : #{params['receipt_email'].inspect}"
  puts "            (all params)      : #{params.inspect}"

  if payment_intent_id.nil?
    status 400
    return log_error("POST /update_payment_intent", "'payment_intent_id' is a required parameter")
  end

  log_connect_context("POST /update_payment_intent", "updating PaymentIntent on connected account")

  begin
    allowed_keys  = ["receipt_email"]
    update_params = params.select { |k, _| allowed_keys.include?(k) }

    puts "[#{ts}] Filtered update params (allowed keys only): #{update_params.inspect}"
    log_stripe_request("POST /update_payment_intent", "Stripe::PaymentIntent.update(#{payment_intent_id})", update_params, connected_account_request_opts)
    payment_intent = Stripe::PaymentIntent.update(payment_intent_id, update_params, connected_account_request_opts)
    log_stripe_response("POST /update_payment_intent", "PaymentIntent (updated)", payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /update_payment_intent", "Failed to update PaymentIntent", e)
  end

  response_payload = { :intent => payment_intent.id, :secret => payment_intent.client_secret }
  puts "[#{ts}] SUCCESS  payment_intent_id=#{payment_intent_id} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /create_recurring_payment
# ─────────────────────────────────────────────────────────────────────────────

post '/create_recurring_payment' do
  log_section("POST /create_recurring_payment")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_recurring_payment", validationError)
  end

  payment_method_id = params[:payment_method_id]
  customer_id       = params[:customer_id]
  amount            = params[:amount]

  puts "[#{ts}] Input params received:"
  puts "            payment_method_id : #{payment_method_id.inspect}"
  puts "            customer_id       : #{customer_id.inspect}"
  puts "            amount            : #{amount.inspect}"
  puts "            currency          : #{params[:currency].inspect}"
  puts "            description       : #{params[:description].inspect}"
  puts "            receipt_email     : #{params[:receipt_email].inspect}"
  puts "            metadata          : #{params[:metadata].inspect}"

  if payment_method_id.nil? || payment_method_id.strip.empty?
    status 400
    return log_error("POST /create_recurring_payment", "'payment_method_id' is required")
  end
  if customer_id.nil? || customer_id.strip.empty?
    status 400
    return log_error("POST /create_recurring_payment", "'customer_id' is required")
  end
  if amount.nil? || amount.to_s.strip.empty?
    status 400
    return log_error("POST /create_recurring_payment", "'amount' is required")
  end

  log_connect_context("POST /create_recurring_payment", "creating off-session PaymentIntent for saved card_present")

  begin
    request_opts = connected_account_request_opts

    # generated_card payment methods are of type 'card' (not 'card_present').
    # card_present requires the physical card to be present and cannot be used off-session.
    pi_params = {
      :amount               => amount.to_i,
      :currency             => params[:currency] || 'usd',
      :customer             => customer_id,
      :payment_method       => payment_method_id,
      :payment_method_types => ['card'],
      :confirm              => true,
      :off_session          => true,
      :capture_method       => 'automatic',
    }

    pi_params[:description]   = params[:description]   if params[:description]   && !params[:description].to_s.strip.empty?
    pi_params[:receipt_email] = params[:receipt_email] if params[:receipt_email] && !params[:receipt_email].to_s.strip.empty?
    pi_params[:metadata]      = params[:metadata]      if params[:metadata]      && !params[:metadata].empty?

    puts "[#{ts}] Final PaymentIntent params being sent to Stripe:"
    pi_params.each { |k, v| puts "            #{k}: #{v.inspect}" }
    puts "[#{ts}] Request opts: #{request_opts.inspect}"

    log_stripe_request("POST /create_recurring_payment", "Stripe::PaymentIntent.create", pi_params, request_opts)
    payment_intent = Stripe::PaymentIntent.create(pi_params, request_opts)
    log_stripe_response("POST /create_recurring_payment", "PaymentIntent (recurring off-session)", payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_recurring_payment", "Failed to create off-session recurring PaymentIntent", e)
  end

  response_payload = {
    :intent   => payment_intent.id,
    :status   => payment_intent.status,
    :amount   => payment_intent.amount,
    :currency => payment_intent.currency,
  }
  puts "[#{ts}] SUCCESS  payment_intent_id=#{payment_intent.id} | status=#{payment_intent.status} | customer_id=#{customer_id} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  content_type :json
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# GET /list_locations
# ─────────────────────────────────────────────────────────────────────────────

get '/list_locations' do
  log_section("GET /list_locations")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("GET /list_locations", validationError)
  end

  log_connect_context("GET /list_locations", "listing Terminal locations on connected account")

  begin
    list_params = { limit: 100 }
    log_stripe_request("GET /list_locations", "Stripe::Terminal::Location.list", list_params, connected_account_request_opts)
    locations = Stripe::Terminal::Location.list(list_params, connected_account_request_opts)
    puts "[#{ts}] <<< STRIPE RESPONSE  [GET /list_locations]  count=#{locations.data.size}"
    locations.data.each_with_index do |loc, i|
      puts "            [#{i}] id=#{loc.id} | display_name=#{loc.display_name}"
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("GET /list_locations", "Failed to fetch Locations", e)
  end

  puts "[#{ts}] SUCCESS  count=#{locations.data.size} | account=#{CONNECTED_ACCOUNT_ID}"
  status 200
  content_type :json
  return locations.data.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /create_location
# ─────────────────────────────────────────────────────────────────────────────

post '/create_location' do
  log_section("POST /create_location")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_location", validationError)
  end

  puts "[#{ts}] Input params received:"
  puts "            display_name : #{params[:display_name].inspect}"
  puts "            address      : #{params[:address].inspect}"

  log_connect_context("POST /create_location", "creating Terminal location on connected account")

  begin
    location_params = {
      display_name: params[:display_name],
      address:      params[:address],
    }

    puts "[#{ts}] Location params being sent to Stripe:"
    location_params.each { |k, v| puts "            #{k}: #{v.inspect}" }

    log_stripe_request("POST /create_location", "Stripe::Terminal::Location.create", location_params, connected_account_request_opts)
    location = Stripe::Terminal::Location.create(location_params, connected_account_request_opts)
    log_stripe_response("POST /create_location", "Terminal::Location", location)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_location", "Failed to create Location", e)
  end

  puts "[#{ts}] SUCCESS  location_id=#{location.id} | account=#{CONNECTED_ACCOUNT_ID}"
  status 200
  content_type :json
  return location.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /create_payment_intent_for_subscription
#
# Creates a PaymentIntent specifically designed to save the card after an
# in-person Tap to Pay payment for future subscription billing.
#
# Required params:
#   amount        - charge amount in cents
#   email         - customer email (used to look up / create a Stripe Customer)
#
# Optional params:
#   currency      - default 'usd'
#   customer_name - customer display name
#   description   - payment description
#
# The PaymentIntent is created with:
#   setup_future_usage: 'off_session'   → instructs Stripe to save the card
#   capture_method: 'automatic'         → auto-captures (no manual capture step)
#
# After the Android SDK collects the payment method (with allowRedisplay='always')
# and confirms the intent, call GET /get_payment_intent?payment_intent_id=pi_xxx
# to retrieve the generated_card PM id for future subscription charges.
# ─────────────────────────────────────────────────────────────────────────────

post '/create_payment_intent_for_subscription' do
  log_section("POST /create_payment_intent_for_subscription")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_payment_intent_for_subscription", validationError)
  end

  amount         = params[:amount]
  customer_email = params[:email] || params[:receipt_email]
  customer_name  = params[:customer_name] || params[:name] || params['customer_name'] || params['name']

  puts "[#{ts}] Input params received:"
  puts "            amount        : #{amount.inspect}"
  puts "            email         : #{customer_email.inspect}"
  puts "            customer_name : #{customer_name.inspect}"
  puts "            currency      : #{params[:currency].inspect}"
  puts "            description   : #{params[:description].inspect}"

  if amount.nil? || amount.to_s.strip.empty?
    status 400
    return log_error("POST /create_payment_intent_for_subscription", "'amount' is required")
  end

  log_connect_context("POST /create_payment_intent_for_subscription", "creating subscription-ready PaymentIntent")

  begin
    request_opts = connected_account_request_opts

    puts "[#{ts}] --- Step 1: Resolve/create customer ---"
    customer_id = lookupOrCreateCustomerOnConnectedAccount(customer_email, customer_name)
    puts "[#{ts}] Customer resolved: #{customer_id}"

    pi_params = {
      :amount               => amount.to_i,
      :currency             => params[:currency] || 'usd',
      :customer             => customer_id,
      :payment_method_types => ['card_present'],
      :capture_method       => 'automatic',
      :setup_future_usage   => 'off_session',
    }

    pi_params[:description]   = params[:description] if params[:description] && !params[:description].to_s.strip.empty?
    pi_params[:receipt_email] = customer_email        if customer_email && !customer_email.to_s.strip.empty?

    puts "[#{ts}] --- Step 2: Create PaymentIntent (setup_future_usage=off_session) ---"
    pi_params.each { |k, v| puts "            #{k}: #{v.inspect}" }

    log_stripe_request("POST /create_payment_intent_for_subscription", "Stripe::PaymentIntent.create", pi_params, request_opts)
    payment_intent = Stripe::PaymentIntent.create(pi_params, request_opts)
    log_stripe_response("POST /create_payment_intent_for_subscription", "PaymentIntent", payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_payment_intent_for_subscription", "Failed to create subscription PaymentIntent", e)
  end

  response_payload = {
    :intent      => payment_intent.id,
    :secret      => payment_intent.client_secret,
    :customer_id => customer_id,
  }
  puts "[#{ts}] SUCCESS  payment_intent_id=#{payment_intent.id} | customer_id=#{customer_id} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  content_type :json
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# GET /get_payment_intent
#
# Retrieves a PaymentIntent with its latest_charge expanded so the Android app
# can extract the generated_card payment method id after a successful
# Tap to Pay payment that used setup_future_usage=off_session.
#
# Required query param:
#   payment_intent_id - the PaymentIntent id (pi_xxx)
#
# Response includes:
#   generated_card_id - the reusable 'card' PM id (pm_xxx) attached to the customer
#   customer_id       - Stripe Customer id
#   status            - PaymentIntent status
# ─────────────────────────────────────────────────────────────────────────────

get '/get_payment_intent' do
  log_section("GET /get_payment_intent")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("GET /get_payment_intent", validationError)
  end

  payment_intent_id = params[:payment_intent_id] || params['payment_intent_id']

  puts "[#{ts}] Input params received:"
  puts "            payment_intent_id : #{payment_intent_id.inspect}"

  if payment_intent_id.nil? || payment_intent_id.to_s.strip.empty?
    status 400
    return log_error("GET /get_payment_intent", "'payment_intent_id' is required")
  end

  log_connect_context("GET /get_payment_intent", "retrieving PaymentIntent with latest_charge expanded")

  begin
    request_opts = connected_account_request_opts
    retrieve_params = { expand: ['latest_charge'] }

    log_stripe_request("GET /get_payment_intent", "Stripe::PaymentIntent.retrieve(#{payment_intent_id})", retrieve_params, request_opts)
    payment_intent = Stripe::PaymentIntent.retrieve({ id: payment_intent_id, expand: ['latest_charge'] }, request_opts)
    log_stripe_response("GET /get_payment_intent", "PaymentIntent (expanded)", payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("GET /get_payment_intent", "Failed to retrieve PaymentIntent", e)
  end

  generated_card_id = nil
  begin
    charge = payment_intent.latest_charge
    if charge && charge.respond_to?(:payment_method_details)
      card_present = charge.payment_method_details&.card_present
      generated_card_id = card_present&.generated_card
    end
  rescue => ex
    puts "[#{ts}] [WARNING] Could not extract generated_card: #{ex.message}"
  end

  puts "[#{ts}] generated_card_id=#{generated_card_id.inspect} | customer=#{payment_intent.customer.inspect} | status=#{payment_intent.status}"

  response_payload = {
    :payment_intent_id  => payment_intent.id,
    :status             => payment_intent.status,
    :customer_id        => payment_intent.customer,
    :generated_card_id  => generated_card_id,
    :amount             => payment_intent.amount,
    :currency           => payment_intent.currency,
  }
  puts "[#{ts}] SUCCESS  account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  content_type :json
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# GET /list_customer_payment_methods
#
# Lists all saved 'card' payment methods for a customer.
# These are the generated_card methods saved from prior Tap to Pay payments.
#
# Required query param:
#   customer_id - Stripe Customer id (cus_xxx)
#
# Optional:
#   email - if customer_id is not known, look up by email instead
# ─────────────────────────────────────────────────────────────────────────────

get '/list_customer_payment_methods' do
  log_section("GET /list_customer_payment_methods")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("GET /list_customer_payment_methods", validationError)
  end

  customer_id = params[:customer_id] || params['customer_id']
  email       = params[:email] || params['email']

  puts "[#{ts}] Input params received:"
  puts "            customer_id : #{customer_id.inspect}"
  puts "            email       : #{email.inspect}"

  begin
    request_opts = connected_account_request_opts

    if customer_id.nil? || customer_id.to_s.strip.empty?
      if email && !email.to_s.strip.empty?
        puts "[#{ts}] No customer_id — resolving via email=#{email}"
        customer_id = lookupOrCreateCustomerOnConnectedAccount(email)
      else
        status 400
        return log_error("GET /list_customer_payment_methods", "'customer_id' or 'email' is required")
      end
    end

    list_params = { customer: customer_id, type: 'card', limit: 20 }
    log_stripe_request("GET /list_customer_payment_methods", "Stripe::PaymentMethod.list", list_params, request_opts)
    payment_methods = Stripe::PaymentMethod.list(list_params, request_opts)
    log_stripe_response("GET /list_customer_payment_methods", "PaymentMethod list", payment_methods)

    puts "[#{ts}] Found #{payment_methods.data.size} saved card(s) for customer_id=#{customer_id}"
    payment_methods.data.each_with_index do |pm, i|
      card = pm.card rescue nil
      puts "            [#{i}] pm_id=#{pm.id} | brand=#{card&.brand} | last4=#{card&.last4} | exp=#{card&.exp_month}/#{card&.exp_year}"
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("GET /list_customer_payment_methods", "Failed to list payment methods", e)
  end

  response_payload = {
    :customer_id     => customer_id,
    :payment_methods => payment_methods.data.map do |pm|
      card = pm.card rescue nil
      {
        :id         => pm.id,
        :brand      => card&.brand,
        :last4      => card&.last4,
        :exp_month  => card&.exp_month,
        :exp_year   => card&.exp_year,
        :created    => pm.created,
      }
    end,
  }
  puts "[#{ts}] SUCCESS  customer_id=#{customer_id} | count=#{payment_methods.data.size} | account=#{CONNECTED_ACCOUNT_ID}"
  status 200
  content_type :json
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /create_subscription
#
# Creates a Stripe Subscription for a customer using a saved generated_card
# payment method from a prior Tap to Pay payment.
#
# Required params:
#   customer_id        - Stripe Customer id (cus_xxx)
#   payment_method_id  - generated_card PM id (pm_xxx) — must be a 'card' type
#   price_id           - Stripe Price id (price_xxx) OR use amount+interval to
#                        auto-create a price
#
# Optional (used when price_id is not provided):
#   amount             - amount in cents (e.g. 2999 for $29.99)
#   currency           - default 'usd'
#   interval           - 'month' | 'week' | 'year' (default 'month')
#   interval_count     - number of intervals between billings (default 1)
#   product_name       - name of the product/service (default 'Carwash Subscription')
#   trial_period_days  - optional free trial days
#   description        - subscription description / metadata note
# ─────────────────────────────────────────────────────────────────────────────

post '/create_subscription' do
  log_section("POST /create_subscription")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_subscription", validationError)
  end

  customer_id       = params[:customer_id]
  payment_method_id = params[:payment_method_id]
  price_id          = params[:price_id]
  amount            = params[:amount]

  puts "[#{ts}] Input params received:"
  puts "            customer_id        : #{customer_id.inspect}"
  puts "            payment_method_id  : #{payment_method_id.inspect}"
  puts "            price_id           : #{price_id.inspect}"
  puts "            amount             : #{amount.inspect}"
  puts "            currency           : #{params[:currency].inspect}"
  puts "            interval           : #{params[:interval].inspect}"
  puts "            interval_count     : #{params[:interval_count].inspect}"
  puts "            product_name       : #{params[:product_name].inspect}"
  puts "            trial_period_days  : #{params[:trial_period_days].inspect}"
  puts "            description        : #{params[:description].inspect}"

  if customer_id.nil? || customer_id.to_s.strip.empty?
    status 400
    return log_error("POST /create_subscription", "'customer_id' is required")
  end
  if payment_method_id.nil? || payment_method_id.to_s.strip.empty?
    status 400
    return log_error("POST /create_subscription", "'payment_method_id' is required (use the generated_card id from /get_payment_intent)")
  end
  if price_id.nil? && (amount.nil? || amount.to_s.strip.empty?)
    status 400
    return log_error("POST /create_subscription", "Either 'price_id' or 'amount' is required")
  end

  log_connect_context("POST /create_subscription", "creating Stripe Subscription on connected account")

  begin
    request_opts = connected_account_request_opts

    # ── Step 1: Set the payment method as the customer's default ──────────────
    puts "[#{ts}] --- Step 1: Set default payment method on customer ---"
    Stripe::Customer.update(
      customer_id,
      { invoice_settings: { default_payment_method: payment_method_id } },
      request_opts
    )
    puts "[#{ts}] Default payment method set to #{payment_method_id} on #{customer_id}"

    # ── Step 2: Resolve or create Price ───────────────────────────────────────
    if price_id.nil?
      puts "[#{ts}] --- Step 2a: Create Product ---"
      product_name = params[:product_name] || 'Carwash Subscription'
      product = Stripe::Product.create({ name: product_name }, request_opts)
      puts "[#{ts}] Product created: id=#{product.id} | name=#{product.name}"

      puts "[#{ts}] --- Step 2b: Create Price ---"
      price_params = {
        :unit_amount => amount.to_i,
        :currency    => params[:currency] || 'usd',
        :recurring   => {
          :interval       => params[:interval]       || 'month',
          :interval_count => (params[:interval_count] || 1).to_i,
        },
        :product     => product.id,
      }

      log_stripe_request("POST /create_subscription", "Stripe::Price.create", price_params, request_opts)
      price = Stripe::Price.create(price_params, request_opts)
      puts "[#{ts}] Price created: id=#{price.id} | amount=#{price.unit_amount} | interval=#{price.recurring.interval}"
      price_id = price.id
    else
      puts "[#{ts}] --- Step 2: Using existing price_id=#{price_id} ---"
    end

    # ── Step 3: Create the Subscription ──────────────────────────────────────
    puts "[#{ts}] --- Step 3: Create Subscription ---"
    sub_params = {
      :customer               => customer_id,
      :default_payment_method => payment_method_id,
      :items                  => [{ :price => price_id }],
      :payment_settings       => {
        :payment_method_types => ['card'],
        :save_default_payment_method => 'on_subscription',
      },
      :expand => ['latest_invoice.payment_intent'],
    }

    sub_params[:trial_period_days] = params[:trial_period_days].to_i if params[:trial_period_days] && params[:trial_period_days].to_s =~ /\A\d+\z/
    sub_params[:metadata] = { description: params[:description] } if params[:description] && !params[:description].to_s.strip.empty?

    puts "[#{ts}] Subscription params being sent to Stripe:"
    sub_params.each { |k, v| puts "            #{k}: #{v.inspect}" }

    log_stripe_request("POST /create_subscription", "Stripe::Subscription.create", sub_params, request_opts)
    subscription = Stripe::Subscription.create(sub_params, request_opts)
    log_stripe_response("POST /create_subscription", "Subscription", subscription)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_subscription", "Failed to create Subscription", e)
  end

  latest_invoice     = subscription.latest_invoice rescue nil
  latest_pi_status   = latest_invoice&.payment_intent&.status rescue nil

  response_payload = {
    :subscription_id          => subscription.id,
    :status                   => subscription.status,
    :customer_id              => customer_id,
    :price_id                 => price_id,
    :current_period_start     => subscription.current_period_start,
    :current_period_end       => subscription.current_period_end,
    :latest_invoice_status    => latest_invoice&.status,
    :latest_payment_status    => latest_pi_status,
  }
  puts "[#{ts}] SUCCESS  subscription_id=#{subscription.id} | status=#{subscription.status} | customer=#{customer_id} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  content_type :json
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# GET /list_subscriptions
#
# Lists active Stripe Subscriptions for a customer.
#
# Required query param:
#   customer_id - Stripe Customer id (cus_xxx)
#
# Optional:
#   status - filter by status: 'active' | 'canceled' | 'all' (default 'active')
# ─────────────────────────────────────────────────────────────────────────────

get '/list_subscriptions' do
  log_section("GET /list_subscriptions")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("GET /list_subscriptions", validationError)
  end

  customer_id = params[:customer_id] || params['customer_id']
  sub_status  = params[:status] || 'active'

  puts "[#{ts}] Input params received:"
  puts "            customer_id : #{customer_id.inspect}"
  puts "            status      : #{sub_status.inspect}"

  if customer_id.nil? || customer_id.to_s.strip.empty?
    status 400
    return log_error("GET /list_subscriptions", "'customer_id' is required")
  end

  begin
    request_opts = connected_account_request_opts
    list_params  = { customer: customer_id, limit: 20 }
    list_params[:status] = sub_status unless sub_status == 'all'

    log_stripe_request("GET /list_subscriptions", "Stripe::Subscription.list", list_params, request_opts)
    subscriptions = Stripe::Subscription.list(list_params, request_opts)
    log_stripe_response("GET /list_subscriptions", "Subscription list", subscriptions)

    puts "[#{ts}] Found #{subscriptions.data.size} subscription(s) for customer_id=#{customer_id}"
    subscriptions.data.each_with_index do |sub, i|
      puts "            [#{i}] sub_id=#{sub.id} | status=#{sub.status} | period_end=#{sub.current_period_end}"
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("GET /list_subscriptions", "Failed to list subscriptions", e)
  end

  response_payload = {
    :customer_id  => customer_id,
    :subscriptions => subscriptions.data.map do |sub|
      item = sub.items&.data&.first rescue nil
      {
        :id                   => sub.id,
        :status               => sub.status,
        :price_id             => item&.price&.id,
        :amount               => item&.price&.unit_amount,
        :currency             => item&.price&.currency,
        :interval             => item&.price&.recurring&.interval,
        :current_period_start => sub.current_period_start,
        :current_period_end   => sub.current_period_end,
        :trial_end            => sub.trial_end,
        :cancel_at_period_end => sub.cancel_at_period_end,
      }
    end,
  }
  puts "[#{ts}] SUCCESS  customer_id=#{customer_id} | count=#{subscriptions.data.size} | account=#{CONNECTED_ACCOUNT_ID}"
  status 200
  content_type :json
  return response_payload.to_json
end

# ─────────────────────────────────────────────────────────────────────────────
# POST /cancel_subscription
#
# Cancels a Stripe Subscription immediately or at period end.
#
# Required params:
#   subscription_id - Stripe Subscription id (sub_xxx)
#
# Optional params:
#   cancel_at_period_end - 'true' to cancel at end of billing period (default: cancel immediately)
# ─────────────────────────────────────────────────────────────────────────────

post '/cancel_subscription' do
  log_section("POST /cancel_subscription")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /cancel_subscription", validationError)
  end

  subscription_id      = params[:subscription_id]
  cancel_at_period_end = params[:cancel_at_period_end].to_s.downcase == 'true'

  puts "[#{ts}] Input params received:"
  puts "            subscription_id      : #{subscription_id.inspect}"
  puts "            cancel_at_period_end : #{cancel_at_period_end.inspect}"

  if subscription_id.nil? || subscription_id.to_s.strip.empty?
    status 400
    return log_error("POST /cancel_subscription", "'subscription_id' is required")
  end

  log_connect_context("POST /cancel_subscription", "canceling Stripe Subscription on connected account")

  begin
    request_opts = connected_account_request_opts

    if cancel_at_period_end
      puts "[#{ts}] Canceling at period end (update cancel_at_period_end=true)"
      log_stripe_request("POST /cancel_subscription", "Stripe::Subscription.update(#{subscription_id})", { cancel_at_period_end: true }, request_opts)
      subscription = Stripe::Subscription.update(subscription_id, { cancel_at_period_end: true }, request_opts)
    else
      puts "[#{ts}] Canceling immediately"
      log_stripe_request("POST /cancel_subscription", "Stripe::Subscription.cancel(#{subscription_id})", {}, request_opts)
      subscription = Stripe::Subscription.cancel(subscription_id, {}, request_opts)
    end

    log_stripe_response("POST /cancel_subscription", "Subscription (canceled)", subscription)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /cancel_subscription", "Failed to cancel Subscription", e)
  end

  response_payload = {
    :subscription_id     => subscription.id,
    :status              => subscription.status,
    :cancel_at_period_end => subscription.cancel_at_period_end,
    :canceled_at         => subscription.canceled_at,
    :current_period_end  => subscription.current_period_end,
  }
  puts "[#{ts}] SUCCESS  subscription_id=#{subscription_id} | status=#{subscription.status} | account=#{CONNECTED_ACCOUNT_ID}"
  puts "[#{ts}] Response to client: #{response_payload.to_json}"
  status 200
  content_type :json
  return response_payload.to_json
end
