# Prevent Sinatra from parsing command-line arguments that might cause issues
# We'll configure the port and bind address directly in code
ARGV.clear if ARGV.any?

require 'sinatra'
require 'stripe'
require 'dotenv'
require 'json'
require 'sinatra/cross_origin'
require 'rack/protection'

# Set the port from environment variable or default to 4567
# This ensures compatibility with Railway, Render, Heroku, and other platforms
set :port, ENV['PORT'] ? ENV['PORT'].to_i : 4567
set :bind, '0.0.0.0'

# Load environment variables
# Load .env file if it exists (for local development)
Dotenv.load if File.exist?('.env')

# Production/Environment Configuration
PRODUCTION = ENV['RACK_ENV'] == 'production' || ENV['ENVIRONMENT'] == 'production'
STRIPE_ENV = ENV['STRIPE_ENV'] || (PRODUCTION ? 'production' : 'test')

# Stripe Configuration
if STRIPE_ENV == 'production'
  Stripe.api_key = ENV['STRIPE_SECRET_KEY'] || ENV['STRIPE_LIVE_SECRET_KEY']
else
  Stripe.api_key = ENV['STRIPE_TEST_SECRET_KEY']
end
Stripe.api_version = '2020-03-02'

# Production Configuration Validation
if PRODUCTION
  if Stripe.api_key.nil? || Stripe.api_key.empty? || !Stripe.api_key.start_with?('sk_live')
    puts "\n⚠️  WARNING: STRIPE_SECRET_KEY should be set to your live key (sk_live_...) in production!\n\n"
  end
end

# Security: Enable protection against common attacks
configure do
  enable :cross_origin
  enable :sessions
  set :protection, :except => [:json_csrf] # CORS handles cross-origin for API
end

# CORS Configuration - Allow all origins
before do
  response.headers['Access-Control-Allow-Origin'] = '*'
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept'
  response.headers['Access-Control-Max-Age'] = '3600'
  
  # Security headers
  response.headers['X-Content-Type-Options'] = 'nosniff'
  response.headers['X-Frame-Options'] = 'DENY'
  response.headers['X-XSS-Protection'] = '1; mode=block'
  if PRODUCTION
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
  end
end

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token"
  response.headers["Access-Control-Allow-Origin"] = "*"
  status 200
end

def log_info(message)
  puts "\n" + message + "\n\n"
  return message
end

# Log whether request is for connected account or platform, and optional step description.
def log_connect_context(endpoint, stripe_account_id, step = nil)
  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  msg = "[#{endpoint}] connected_account=#{connected ? 'yes' : 'no'}"
  msg += " (stripe_account_id=#{stripe_account_id.strip})" if connected && stripe_account_id
  msg += " | #{step}" if step
  log_info(msg)
end

# Log error with endpoint name and full exception details.
def log_error(endpoint, message, exception = nil)
  full = "[#{endpoint}] Error: #{message}"
  full += " | Exception: #{exception.class} - #{exception.message}" if exception
  log_info(full)
  return full
end

get '/' do
  status 404
  content_type :json
  {:error => 'Not Found', :message => 'This service is not available.'}.to_json
end

def validateApiKey
  if Stripe.api_key.nil? || Stripe.api_key.empty?
    mode = STRIPE_ENV == 'production' ? 'production' : 'test'
    return "Error: you provided an empty secret key. Please provide your #{mode} mode secret key. For more information, see https://stripe.com/docs/keys"
  end
  if Stripe.api_key.start_with?('pk')
    return "Error: you used a publishable key to set up the backend. Please use your secret key. For more information, see https://stripe.com/docs/keys"
  end
  # Production validation: ensure key matches environment
  if STRIPE_ENV == 'production'
    unless Stripe.api_key.start_with?('sk_live')
      return "Error: you are in production mode but using a test key. Please use your live mode secret key (sk_live_...). For more information, see https://stripe.com/docs/keys#test-live-modes"
    end
  else
    # Test mode: ensure key matches environment
    if Stripe.api_key.start_with?('sk_live')
      return "Error: you are in test mode but using a live key. Please use your test mode secret key (sk_test_...). For more information, see https://stripe.com/docs/keys#test-live-modes"
    end
    unless Stripe.api_key.start_with?('sk_test')
      return "Error: invalid secret key format. Please use your test mode secret key (sk_test_...). For more information, see https://stripe.com/docs/keys"
    end
  end
  return nil
end

# This endpoint registers a Verifone P400 reader to your Stripe account.
# https://stripe.com/docs/terminal/readers/connecting/verifone-p400#register-reader
# Optional: stripe_account_id - register the reader on this connected account (direct charges).
post '/register_reader' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /register_reader", validationError)
  end

  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  log_connect_context("POST /register_reader", stripe_account_id, "Step: registering reader")

  begin
    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.to_s.strip.empty?

    reader_params = {
      :registration_code => params[:registration_code],
      :label => params[:label],
      :location => params[:location]
    }
    reader = Stripe::Terminal::Reader.create(reader_params, request_opts)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /register_reader", "Failed to register reader", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[POST /register_reader] Success: reader_id=#{reader.id} | connected_account=#{connected ? 'yes' : 'no'}")
  status 200
  # Note that returning the Stripe reader object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  return reader.to_json
end

# This endpoint creates a ConnectionToken, which gives the SDK permission
# to use a reader with your Stripe account.
# https://stripe.com/docs/terminal/sdk/js#connection-token
# https://stripe.com/docs/terminal/features/connect#direct-connection-tokens
#
# Optional params:
#   stripe_account_id - Create token for this connected account (direct charges).
#   location          - Scope token to this Terminal location (readers at this location only).
post '/connection_token' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /connection_token", validationError)
  end

  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  location_id = params[:location] || params['location_id']
  log_connect_context("POST /connection_token", stripe_account_id, "Step: creating connection token" + (location_id && !location_id.to_s.strip.empty? ? " (location=#{location_id})" : ""))

  begin
    token_params = {}
    token_params[:location] = location_id.strip if location_id && !location_id.to_s.strip.empty?

    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.strip.empty?

    if request_opts.empty?
      token = Stripe::Terminal::ConnectionToken.create(token_params)
      log_info("[POST /connection_token] Step: created token on platform")
    else
      log_info("[POST /connection_token] Step: creating token for connected account #{stripe_account_id}")
      token = Stripe::Terminal::ConnectionToken.create(token_params, request_opts)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /connection_token", "Failed to create ConnectionToken", e)
  end

  log_info("[POST /connection_token] Success: connected_account=#{request_opts.empty? ? 'no' : 'yes'}")
  content_type :json
  status 200
  return {:secret => token.secret}.to_json
end

# This endpoint creates a PaymentIntent.
# https://stripe.com/docs/terminal/payments#create
# https://stripe.com/docs/terminal/features/connect#direct-payment-intents-server-side
#
# Connected accounts:
#   stripe_account_id - When set, create customer on connected account and create PaymentIntent on connected account (direct charge).
#   Settlement merchant will be the connected account (no transfer). If no customer/email, we create a customer on connected account first.
#   customer_name or name - Optional. Display name for the customer in Stripe dashboard (e.g. "Gsgss"); avoids showing "walk-in@terminal.local".
# Looks up or creates a Customer on your stripe account with the provided email (platform only).
def lookupOrCreateCustomer(customerEmail)
  return nil if customerEmail.nil? || customerEmail.empty?
  
  begin
    customerList = Stripe::Customer.list(email: customerEmail, limit: 1).data
    if (customerList.length == 1)
      return customerList[0]
    else
      return Stripe::Customer.create(email: customerEmail)
    end
  rescue Stripe::StripeError => e
    log_error("lookupOrCreateCustomer", "Creating or retrieving customer", e)
    return nil
  end
end

# Look up or create a Customer on the connected account. Used so the PaymentIntent is created on the connected account
# with a customer (settlement merchant = connected account). Returns the customer id on the connected account.
# customer_name (optional): display name for the customer in Stripe dashboard (e.g. "Gsgss"); use params customer_name or name.
def lookupOrCreateCustomerOnConnectedAccount(customerEmail, stripe_account_id, customer_name = nil)
  request_opts = { stripe_account: stripe_account_id.strip }
  email = customerEmail.to_s.strip
  email = nil if email.empty?
  name = customer_name.to_s.strip
  name = nil if name.empty?
  begin
    if email
      customerList = Stripe::Customer.list({ email: email, limit: 1 }, request_opts).data
      if customerList.length >= 1
        cid = customerList[0].id
        if name
          Stripe::Customer.update(cid, { name: name }, request_opts)
          log_info("[lookupOrCreateCustomerOnConnectedAccount] Updated existing customer name on connected account: #{cid} (name=#{name})")
        else
          log_info("[lookupOrCreateCustomerOnConnectedAccount] Found existing customer on connected account: #{cid}")
        end
        return cid
      end
      create_params = { email: email }
      create_params[:name] = name if name
      newCustomer = Stripe::Customer.create(create_params, request_opts)
      log_info("[lookupOrCreateCustomerOnConnectedAccount] Created new customer on connected account: #{newCustomer.id} (email=#{email}#{name ? ", name=#{name}" : ''})")
      return newCustomer.id
    else
      create_params = { metadata: { source: "terminal_walkin" } }
      if name
        create_params[:name] = name
        create_params[:email] = "walk-in@terminal.local"
      else
        create_params[:email] = "walk-in@terminal.local"
      end
      newCustomer = Stripe::Customer.create(create_params, request_opts)
      log_info("[lookupOrCreateCustomerOnConnectedAccount] Created walk-in customer on connected account: #{newCustomer.id}#{name ? " (name=#{name})" : ''}")
      return newCustomer.id
    end
  rescue Stripe::StripeError => e
    log_error("lookupOrCreateCustomerOnConnectedAccount", "Creating or retrieving customer on connected account", e)
    raise
  end
end

post '/create_payment_intent' do
  # Log all received data from the triggering call
  log_info("=== create_payment_intent triggered ===\nFull received params: #{params.inspect}\nRaw request body: #{request.body.read rescue 'N/A'}\nLocation ID: #{params[:location_id] || params['location_id'] || 'not provided'}\nOrder ID: #{params[:order_id] || params['order_id'] || 'not provided'}\nTags: #{params[:tags] || params['tags'] || 'not provided'}\nAll param keys: #{params.keys.inspect}")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_payment_intent", validationError)
  end

  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  use_direct_charge = stripe_account_id && !stripe_account_id.strip.empty?
  log_connect_context("POST /create_payment_intent", stripe_account_id, "direct_charge=#{use_direct_charge} | Step: creating PaymentIntent (settlement on connected account when present)")

  begin
    customer_email = params[:email] || params[:receipt_email]
    customer_name = params[:customer_name] || params[:name] || params['customer_name'] || params['name']
    payment_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
      :capture_method => params[:capture_method] || 'manual',
      :amount => params[:amount],
      :currency => params[:currency] || 'usd',
      :description => params[:description] || 'Example PaymentIntent',
      :payment_method_options => params[:payment_method_options] || [],
      :receipt_email => customer_email,
    }

    request_opts = {}
    if use_direct_charge
      # Direct charge: create customer on connected account (clone/lookup or create), then create PI on connected account.
      # No transfer — settlement merchant will be the connected account.
      request_opts[:stripe_account] = stripe_account_id.strip
      connected_customer_id = lookupOrCreateCustomerOnConnectedAccount(customer_email, stripe_account_id, customer_name)
      payment_intent_params[:customer] = connected_customer_id
      log_info("[POST /create_payment_intent] Step: created/lookup customer on connected account (#{connected_customer_id}), creating PaymentIntent on connected account")
      log_info("[POST /create_payment_intent] IMPORTANT: For the reader to complete this payment, your app MUST request the connection token with the SAME stripe_account_id (call POST /connection_token with stripe_account_id=#{stripe_account_id}). Reader and PaymentIntent must be on the same account.")
    else
      # Platform: optional customer on platform
      customer = nil
      customer = lookupOrCreateCustomer(customer_email) if customer_email
      payment_intent_params[:customer] = customer.id if customer
    end
    
    if params[:metadata] && !params[:metadata].empty?
      payment_intent_params[:metadata] = params[:metadata]
    end
    
    payment_intent = Stripe::PaymentIntent.create(payment_intent_params, request_opts.empty? ? {} : request_opts)
    
    # Update description to only contain the PaymentIntent ID
    update_opts = request_opts.empty? ? {} : request_opts
    payment_intent = Stripe::PaymentIntent.update(
      payment_intent.id,
      { description: payment_intent.id },
      update_opts
    )
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_payment_intent", "Failed to create PaymentIntent", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[POST /create_payment_intent] Success: payment_intent_id=#{payment_intent.id} | connected_account=#{connected ? 'yes' : 'no'} | settlement_merchant=#{use_direct_charge ? 'connected_account' : 'platform'}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint captures a PaymentIntent.
# https://stripe.com/docs/terminal/payments#capture
# Optional: stripe_account_id - required when the PaymentIntent was created on a connected account (direct charge).
post '/capture_payment_intent' do
  id = params["payment_intent_id"]
  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  log_connect_context("POST /capture_payment_intent", stripe_account_id, "Step: capturing payment_intent_id=#{id}")

  begin
    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.to_s.strip.empty?

    if !params["amount_to_capture"].nil?
      payment_intent = Stripe::PaymentIntent.capture(id, { amount_to_capture: params["amount_to_capture"] }, request_opts)
    else
      payment_intent = Stripe::PaymentIntent.capture(id, {}, request_opts)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /capture_payment_intent", "Failed to capture PaymentIntent", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[POST /capture_payment_intent] Success: payment_intent_id=#{id} | connected_account=#{connected ? 'yes' : 'no'}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint cancels a PaymentIntent.
# https://stripe.com/docs/api/payment_intents/cancel
# Optional: stripe_account_id - required when the PaymentIntent was created on a connected account (direct charge).
post '/cancel_payment_intent' do
  id = params["payment_intent_id"]
  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  log_connect_context("POST /cancel_payment_intent", stripe_account_id, "Step: canceling payment_intent_id=#{id}")

  begin
    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.to_s.strip.empty?
    payment_intent = Stripe::PaymentIntent.cancel(id, {}, request_opts)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /cancel_payment_intent", "Failed to cancel PaymentIntent", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[POST /cancel_payment_intent] Success: payment_intent_id=#{id} | connected_account=#{connected ? 'yes' : 'no'}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint creates a SetupIntent.
# https://stripe.com/docs/api/setup_intents/create
# Optional: stripe_account_id - create the SetupIntent on this connected account (direct charges).
post '/create_setup_intent' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_setup_intent", validationError)
  end

  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  log_connect_context("POST /create_setup_intent", stripe_account_id, "Step: creating SetupIntent")

  begin
    setup_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
    }

    if !params[:customer].nil?
      setup_intent_params[:customer] = params[:customer]
    end

    if !params[:description].nil?
      setup_intent_params[:description] = params[:description]
    end

    if !params[:on_behalf_of].nil?
      setup_intent_params[:on_behalf_of] = params[:on_behalf_of]
    end

    stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.to_s.strip.empty?

    setup_intent = Stripe::SetupIntent.create(setup_intent_params, request_opts)

  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_setup_intent", "Failed to create SetupIntent", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[POST /create_setup_intent] Success: setup_intent_id=#{setup_intent.id} | connected_account=#{connected ? 'yes' : 'no'}")
  status 200
  return {:intent => setup_intent.id, :secret => setup_intent.client_secret}.to_json
end

# Looks up or creates a Customer on your stripe account
# with email "example@test.com".
def lookupOrCreateExampleCustomer
  customerEmail = "example@test.com"
  begin
    customerList = Stripe::Customer.list(email: customerEmail, limit: 1).data
    if (customerList.length == 1)
      return customerList[0]
    else
      return Stripe::Customer.create(email: customerEmail)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("lookupOrCreateExampleCustomer", "Creating or retrieving example customer", e)
  end
end

# This endpoint attaches a PaymentMethod to a Customer.
# https://stripe.com/docs/terminal/payments/saving-cards#read-reusable-card
post '/attach_payment_method_to_customer' do
  begin
    customer = lookupOrCreateExampleCustomer

    payment_method = Stripe::PaymentMethod.attach(
      params[:payment_method_id],
      {
        customer: customer.id,
        expand: ["customer"],
    })
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /attach_payment_method_to_customer", "Failed to attach PaymentMethod to Customer", e)
  end

  log_info("[POST /attach_payment_method_to_customer] Success: customer_id=#{customer.id} (platform)")

  status 200
  # Note that returning the Stripe payment_method object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  return payment_method.to_json
end

# This endpoint updates the PaymentIntent represented by 'payment_intent_id'.
# It currently only supports updating the 'receipt_email' property.
# Optional: stripe_account_id - required when the PaymentIntent was created on a connected account (direct charge).
#
# https://stripe.com/docs/api/payment_intents/update
post '/update_payment_intent' do
  payment_intent_id = params["payment_intent_id"]
  if payment_intent_id.nil?
    status 400
    return log_error("POST /update_payment_intent", "'payment_intent_id' is a required parameter")
  end

  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  log_connect_context("POST /update_payment_intent", stripe_account_id, "Step: updating payment_intent_id=#{payment_intent_id}")

  begin
    allowed_keys = ["receipt_email"]
    update_params = params.select { |k, _| allowed_keys.include?(k) }

    stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.to_s.strip.empty?

    payment_intent = Stripe::PaymentIntent.update(
      payment_intent_id,
      update_params,
      request_opts
    )

    log_info("Updated PaymentIntent #{payment_intent_id}")
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /update_payment_intent", "Failed to update PaymentIntent", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[POST /update_payment_intent] Success: payment_intent_id=#{payment_intent_id} | connected_account=#{connected ? 'yes' : 'no'}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint lists the first 100 Locations. If you will have more than 100
# Locations, you'll likely want to implement pagination in your application so that
# you can efficiently fetch Locations as needed.
# Optional: stripe_account_id - list locations for this connected account (direct charges).
# https://stripe.com/docs/api/terminal/locations
get '/list_locations' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("GET /list_locations", validationError)
  end

  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  log_connect_context("GET /list_locations", stripe_account_id, "Step: listing locations")

  begin
    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.to_s.strip.empty?

    locations = Stripe::Terminal::Location.list(
      { limit: 100 },
      request_opts
    )
  rescue Stripe::StripeError => e
    status 402
    return log_error("GET /list_locations", "Failed to fetch Locations", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[GET /list_locations] Success: count=#{locations.data.size} | connected_account=#{connected ? 'yes' : 'no'}")
  status 200
  content_type :json
  return locations.data.to_json
end

# This endpoint creates a Location.
# https://stripe.com/docs/api/terminal/locations
# Optional: stripe_account_id - create the location on this connected account (direct charges).
post '/create_location' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_location", validationError)
  end

  stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']
  log_connect_context("POST /create_location", stripe_account_id, "Step: creating location")

  begin
    request_opts = {}
    request_opts[:stripe_account] = stripe_account_id.strip if stripe_account_id && !stripe_account_id.to_s.strip.empty?

    location_params = {
      display_name: params[:display_name],
      address: params[:address]
    }
    location = Stripe::Terminal::Location.create(location_params, request_opts)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_location", "Failed to create Location", e)
  end

  connected = stripe_account_id && !stripe_account_id.to_s.strip.empty?
  log_info("[POST /create_location] Success: location_id=#{location.id} | connected_account=#{connected ? 'yes' : 'no'}")
  status 200
  content_type :json
  return location.to_json
end
