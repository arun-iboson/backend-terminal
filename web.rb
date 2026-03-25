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
Stripe.api_version = '2023-10-16'

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

# Log connected-account context and optional step description.
def log_connect_context(endpoint, step = nil)
  msg = "[#{endpoint}] stripe_account_id=#{CONNECTED_ACCOUNT_ID}"
  msg += " | #{step}" if step
  log_info(msg)
end

# Normalize nested objects for logs (hashes, Stripe objects).
def inspect_for_stripe_log(obj)
  case obj
  when Hash
    obj.transform_values { |v| inspect_for_stripe_log(v) }
  when Array
    obj.map { |v| inspect_for_stripe_log(v) }
  when Stripe::StripeObject
    (obj.to_hash rescue nil) || obj.inspect
  else
    obj
  end
end

# Log outbound Stripe API arguments (no platform secret key — only call bodies + stripe_account).
def log_stripe_request(http_endpoint_label, stripe_operation, params_for_stripe, request_opts = nil)
  opts = request_opts ? inspect_for_stripe_log(request_opts) : nil
  body = inspect_for_stripe_log(params_for_stripe)
  log_info("[STRIPE → #{http_endpoint_label}] #{stripe_operation}\nrequest_opts=#{opts.inspect}\nparams=#{body.inspect}")
end

# Log PaymentIntent fields after create/update (client_secret truncated).
def log_payment_intent_stripe_response(http_endpoint_label, step, pi)
  return unless pi
  sec = pi.respond_to?(:client_secret) && pi.client_secret ? "#{pi.client_secret[0..12]}…REDACTED" : nil
  log_info(
    "[STRIPE ← #{http_endpoint_label}] #{step}\n" \
    "id=#{pi.id} status=#{pi.status} amount=#{pi.amount} currency=#{pi.currency} " \
    "customer=#{pi.customer} capture_method=#{pi.capture_method rescue 'n/a'} " \
    "setup_future_usage=#{pi.setup_future_usage rescue 'n/a'} " \
    "payment_method_types=#{(pi.payment_method_types rescue pi['payment_method_types']).inspect} " \
    "latest_charge=#{pi.latest_charge rescue 'n/a'} client_secret=#{sec}"
  )
end

CARD_PRESENT_SAVE_ERROR_HINT = <<~HINT.strip.freeze
  [CAUSE: card_present vs subscription/customer]
  Stripe rejects saving Terminal type `card_present` to Customers or as subscription default_payment_method.
  Use the reusable `generated_card` PaymentMethod (type `card`, id pm_...) from the succeeded charge:
  POST /retrieve_generated_card with payment_intent_id after capture. If this log is from another service
  (e.g. node-postgres-api), fix that service to use generated_card_payment_method_id, not the reader's card_present pm_ id.
HINT

# Log error with endpoint name, full Stripe error payload when applicable, and subscription/card_present cause.
def log_error(endpoint, message, exception = nil)
  lines = ["[#{endpoint}] Error: #{message}"]
  if exception
    lines << "Exception: #{exception.class} - #{exception.message}"
    if exception.is_a?(Stripe::StripeError)
      lines << "stripe_code=#{exception.code}" if exception.respond_to?(:code) && exception.code
      lines << "stripe_http_status=#{exception.http_status}" if exception.respond_to?(:http_status) && exception.http_status
      lines << "stripe_request_id=#{exception.request_id}" if exception.respond_to?(:request_id) && exception.request_id
      if exception.respond_to?(:json_body) && exception.json_body
        lines << "stripe_json_body=#{exception.json_body.inspect}"
      elsif exception.respond_to?(:http_body) && exception.http_body
        lines << "stripe_http_body=#{exception.http_body.inspect}"
      end
      em = exception.message.to_s
      if em.include?('card_present') && (em.include?('cannot be saved') || em.include?('saved to customers'))
        lines << CARD_PRESENT_SAVE_ERROR_HINT
      end
    end
  end
  out = lines.join("\n")
  log_info(out)
  return out
end

get '/' do
  status 404
  content_type :json
  {:error => 'Not Found', :message => 'This service is not available.'}.to_json
end

get '/health' do
  status 200
  content_type :json
  {
    :status => 'ok',
    :stripe_env => STRIPE_ENV,
    :api_version => Stripe.api_version,
    :connected_account => CONNECTED_ACCOUNT_ID,
  }.to_json
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

# This endpoint registers a Verifone P400 reader on the connected account.
# https://stripe.com/docs/terminal/readers/connecting/verifone-p400#register-reader
post '/register_reader' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /register_reader", validationError)
  end

  log_connect_context("POST /register_reader", "Step: registering reader")

  begin
    reader_params = {
      :registration_code => params[:registration_code],
      :label => params[:label],
      :location => params[:location]
    }
    ropts = connected_account_request_opts
    log_stripe_request('POST /register_reader', 'Terminal::Reader.create', reader_params, ropts)
    reader = Stripe::Terminal::Reader.create(reader_params, ropts)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /register_reader", "Failed to register reader", e)
  end

  log_info("[POST /register_reader] Success: reader_id=#{reader.id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  # Note that returning the Stripe reader object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  return reader.to_json
end

# This endpoint creates a ConnectionToken for the connected account Terminal.
# https://stripe.com/docs/terminal/sdk/js#connection-token
# https://stripe.com/docs/terminal/features/connect#direct-connection-tokens
#
# Optional: location / location_id — scope token to this Terminal location.
post '/connection_token' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /connection_token", validationError)
  end

  location_id = params[:location] || params['location_id']
  log_connect_context("POST /connection_token", "Step: creating connection token" + (location_id && !location_id.to_s.strip.empty? ? " (location=#{location_id})" : ""))

  begin
    token_params = {}
    token_params[:location] = location_id.strip if location_id && !location_id.to_s.strip.empty?

    ropts = connected_account_request_opts
    log_stripe_request('POST /connection_token', 'Terminal::ConnectionToken.create', token_params, ropts)
    token = Stripe::Terminal::ConnectionToken.create(token_params, ropts)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /connection_token", "Failed to create ConnectionToken", e)
  end

  log_info("[POST /connection_token] Success: stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  content_type :json
  status 200
  return {:secret => token.secret}.to_json
end

# Look up or create a Customer on the connected account for Terminal payments. Returns the customer id.
# customer_name — optional display name; without email a walk-in customer is created.
def lookupOrCreateCustomerOnConnectedAccount(customerEmail, customer_name = nil)
  request_opts = connected_account_request_opts
  email = customerEmail.to_s.strip
  email = nil if email.empty?
  name = customer_name.to_s.strip
  name = nil if name.empty?
  begin
    if email
      list_q = { email: email, limit: 1 }
      log_stripe_request('lookupOrCreateCustomer', 'Customer.list', list_q, request_opts)
      customerList = Stripe::Customer.list(list_q, request_opts).data
      if customerList.length >= 1
        cid = customerList[0].id
        if name
          upd = { name: name }
          log_stripe_request('lookupOrCreateCustomer', "Customer.update(#{cid})", upd, request_opts)
          Stripe::Customer.update(cid, upd, request_opts)
          log_info("[lookupOrCreateCustomerOnConnectedAccount] Updated existing customer name on connected account: #{cid} (name=#{name})")
        else
          log_info("[lookupOrCreateCustomerOnConnectedAccount] Found existing customer on connected account: #{cid}")
        end
        return cid
      end
      create_params = { email: email }
      create_params[:name] = name if name
      log_stripe_request('lookupOrCreateCustomer', 'Customer.create', create_params, request_opts)
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
      log_stripe_request('lookupOrCreateCustomer', 'Customer.create (walk-in)', create_params, request_opts)
      newCustomer = Stripe::Customer.create(create_params, request_opts)
      log_info("[lookupOrCreateCustomerOnConnectedAccount] Created walk-in customer on connected account: #{newCustomer.id}#{name ? " (name=#{name})" : ''}")
      return newCustomer.id
    end
  rescue Stripe::StripeError => e
    log_error("lookupOrCreateCustomerOnConnectedAccount", "Creating or retrieving customer on connected account", e)
    raise
  end
end

# Creates a PaymentIntent on the connected account (Stripe-Connect direct charge).
# Uses request option stripe_account only — no transfer_data, no separate charges and transfers.
# Funds settle on the connected account; transfer capability on the connected account is not required for this flow.
# https://stripe.com/docs/terminal/payments#create
# https://stripe.com/docs/terminal/features/connect#direct-payment-intents-server-side
post '/create_payment_intent' do
  # Log all received data from the triggering call
  log_info("=== create_payment_intent triggered ===\nFull received params: #{params.inspect}\nRaw request body: #{request.body.read rescue 'N/A'}\nLocation ID: #{params[:location_id] || params['location_id'] || 'not provided'}\nOrder ID: #{params[:order_id] || params['order_id'] || 'not provided'}\nTags: #{params[:tags] || params['tags'] || 'not provided'}\nAll param keys: #{params.keys.inspect}")

  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_payment_intent", validationError)
  end

  log_connect_context("POST /create_payment_intent", "Step: creating PaymentIntent on connected account")

  begin
    customer_email = params[:email] || params[:receipt_email]
    customer_name = params[:customer_name] || params[:name] || params['customer_name'] || params['name']
    payment_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
      :capture_method => params[:capture_method] || 'manual',
      :amount => params[:amount],
      :currency => params[:currency] || 'usd',
      :description => params[:description] || 'Example PaymentIntent',
      :payment_method_options => params[:payment_method_options] || {},
      :receipt_email => customer_email,
    }

    # Save the card_present PaymentMethod on the Customer for future off-session charges
    # (subscriptions / recurring via /create_recurring_payment). Stripe requires
    # setup_future_usage: 'off_session' for charges when the customer will not be present.
    # Native Stripe::Subscription does NOT support card_present.
    # Opt out for strictly one-time sales: pass one_time=true (or one_time=1 / yes).
    one_time = %w[true 1 yes].include?(params[:one_time].to_s.downcase)
    unless one_time
      sfu = params[:setup_future_usage].to_s
      if %w[on_session off_session].include?(sfu)
        payment_intent_params[:setup_future_usage] = sfu
      else
        payment_intent_params[:setup_future_usage] = 'off_session'
      end
    end

    request_opts = connected_account_request_opts
    connected_customer_id = lookupOrCreateCustomerOnConnectedAccount(customer_email, customer_name)
    payment_intent_params[:customer] = connected_customer_id
    log_info("[POST /create_payment_intent] Step: customer #{connected_customer_id} on #{CONNECTED_ACCOUNT_ID}; creating PaymentIntent")
    
    if params[:metadata] && !params[:metadata].empty?
      payment_intent_params[:metadata] = params[:metadata]
    end

    # Direct charge: PI belongs to CONNECTED_ACCOUNT_ID (second arg). No platform transfer.
    log_stripe_request('POST /create_payment_intent', 'PaymentIntent.create', payment_intent_params, request_opts)
    payment_intent = Stripe::PaymentIntent.create(payment_intent_params, request_opts)
    log_payment_intent_stripe_response('POST /create_payment_intent', 'PaymentIntent.create OK', payment_intent)

    # Update description to only contain the PaymentIntent ID
    desc_update = { description: payment_intent.id }
    log_stripe_request('POST /create_payment_intent', "PaymentIntent.update(#{payment_intent.id})", desc_update, request_opts)
    payment_intent = Stripe::PaymentIntent.update(
      payment_intent.id,
      desc_update,
      request_opts
    )
    log_payment_intent_stripe_response('POST /create_payment_intent', 'PaymentIntent.update OK', payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_payment_intent", "Failed to create PaymentIntent", e)
  end

  log_info("[POST /create_payment_intent] Success: payment_intent_id=#{payment_intent.id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint captures a PaymentIntent on the connected account.
# https://stripe.com/docs/terminal/payments#capture
post '/capture_payment_intent' do
  id = params["payment_intent_id"]
  log_connect_context("POST /capture_payment_intent", "Step: capturing payment_intent_id=#{id}")

  begin
    request_opts = connected_account_request_opts

    if !params["amount_to_capture"].nil?
      cap_params = { amount_to_capture: params["amount_to_capture"] }
      log_stripe_request('POST /capture_payment_intent', "PaymentIntent.capture(#{id})", cap_params, request_opts)
      payment_intent = Stripe::PaymentIntent.capture(id, cap_params, request_opts)
    else
      log_stripe_request('POST /capture_payment_intent', "PaymentIntent.capture(#{id})", {}, request_opts)
      payment_intent = Stripe::PaymentIntent.capture(id, {}, request_opts)
    end
    log_payment_intent_stripe_response('POST /capture_payment_intent', 'PaymentIntent.capture OK', payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /capture_payment_intent", "Failed to capture PaymentIntent", e)
  end

  log_info("[POST /capture_payment_intent] Success: payment_intent_id=#{id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# Reusable pm_... (type card) created after an in-person payment when setup_future_usage was set.
# Do NOT use the card_present PaymentMethod from the reader for Customer attach or Subscriptions.
# https://docs.stripe.com/terminal/features/saving-payment-details/save-after-payment
def generated_card_pm_id_from_charge(charge)
  return nil unless charge
  pmd = charge.payment_method_details
  return nil unless pmd
  cp = pmd.respond_to?(:card_present) ? pmd.card_present : nil
  return nil unless cp
  gc = cp.respond_to?(:generated_card) ? cp.generated_card : nil
  return nil if gc.nil? || (gc.respond_to?(:empty?) && gc.empty?)
  return gc if gc.is_a?(String) && gc.start_with?('pm_')
  return gc.id if gc.respond_to?(:id) && gc.id.to_s.start_with?('pm_')
  s = gc.to_s
  s.start_with?('pm_') ? s : nil
end

# Returns the generated_card PaymentMethod id for subscriptions / default_payment_method.
# Call after the Terminal payment succeeds (and after capture if using manual capture).
#
# Required: payment_intent_id (pi_...)
#
# Response includes generated_card_payment_method_id (pm_..., type card) when present.
post '/retrieve_generated_card' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /retrieve_generated_card", validationError)
  end

  payment_intent_id = params[:payment_intent_id] || params['payment_intent_id']
  if payment_intent_id.nil? || payment_intent_id.to_s.strip.empty?
    status 400
    return log_error("POST /retrieve_generated_card", "'payment_intent_id' is required")
  end

  log_connect_context("POST /retrieve_generated_card", "Step: payment_intent_id=#{payment_intent_id}")

  begin
    request_opts = connected_account_request_opts
    retrieve_q = { id: payment_intent_id.strip, expand: ['latest_charge'] }
    log_stripe_request('POST /retrieve_generated_card', 'PaymentIntent.retrieve', retrieve_q, request_opts)
    pi = Stripe::PaymentIntent.retrieve(retrieve_q, request_opts)
    charge = pi.latest_charge
    if charge.is_a?(String)
      log_stripe_request('POST /retrieve_generated_card', "Charge.retrieve(#{charge})", {}, request_opts)
      charge = Stripe::Charge.retrieve(charge, request_opts)
    end
    log_info(
      "[STRIPE ← POST /retrieve_generated_card] after retrieve\n" \
      "pi=#{pi.id} status=#{pi.status} latest_charge=#{charge&.id} " \
      "charge_paid=#{charge&.paid} charge_status=#{charge&.status}"
    )
    pm_id = generated_card_pm_id_from_charge(charge)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /retrieve_generated_card", "Failed to retrieve PaymentIntent", e)
  end

  content_type :json
  if pm_id.nil?
    log_info(
      "[POST /retrieve_generated_card] no_generated_card | pi=#{pi.id} status=#{pi.status} | " \
      "Typical causes: one_time Terminal payment (no setup_future_usage), missing allow_redisplay on reader, " \
      "wallet/unsupported card, or PI not yet succeeded/captured."
    )
    status 422
    return {
      :error => 'no_generated_card',
      :message => 'No generated_card on this charge. Use setup_future_usage off_session on create_payment_intent, collect with allow_redisplay on the reader, complete/capture the payment, then retry. Wallets and some regional cards never produce a generated_card.',
      :payment_intent_id => pi.id,
      :payment_intent_status => pi.status,
      :customer_id => pi.customer,
    }.to_json
  end

  log_info("[POST /retrieve_generated_card] Success: pi=#{pi.id} generated_card=#{pm_id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  return {
    :payment_intent_id => pi.id,
    :payment_intent_status => pi.status,
    :generated_card_payment_method_id => pm_id,
    :customer_id => pi.customer,
  }.to_json
end

# This endpoint cancels a PaymentIntent on the connected account.
# https://stripe.com/docs/api/payment_intents/cancel
post '/cancel_payment_intent' do
  id = params["payment_intent_id"]
  log_connect_context("POST /cancel_payment_intent", "Step: canceling payment_intent_id=#{id}")

  begin
    ropts = connected_account_request_opts
    log_stripe_request('POST /cancel_payment_intent', "PaymentIntent.cancel(#{id})", {}, ropts)
    payment_intent = Stripe::PaymentIntent.cancel(id, {}, ropts)
    log_payment_intent_stripe_response('POST /cancel_payment_intent', 'PaymentIntent.cancel OK', payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /cancel_payment_intent", "Failed to cancel PaymentIntent", e)
  end

  log_info("[POST /cancel_payment_intent] Success: payment_intent_id=#{id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint creates a SetupIntent on the connected account.
# https://stripe.com/docs/api/setup_intents/create
post '/create_setup_intent' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_setup_intent", validationError)
  end

  log_connect_context("POST /create_setup_intent", "Step: creating SetupIntent")

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

    ropts = connected_account_request_opts
    log_stripe_request('POST /create_setup_intent', 'SetupIntent.create', setup_intent_params, ropts)
    setup_intent = Stripe::SetupIntent.create(setup_intent_params, ropts)
    log_info(
      "[STRIPE ← POST /create_setup_intent] SetupIntent.create OK\n" \
      "id=#{setup_intent.id} status=#{setup_intent.status} customer=#{setup_intent.customer} " \
      "payment_method_types=#{setup_intent.payment_method_types.inspect}"
    )

  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_setup_intent", "Failed to create SetupIntent", e)
  end

  log_info("[POST /create_setup_intent] Success: setup_intent_id=#{setup_intent.id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  return {:intent => setup_intent.id, :secret => setup_intent.client_secret}.to_json
end

# Looks up or creates example@test.com Customer on the connected account (saved-card demo).
def lookupOrCreateExampleCustomerOnConnectedAccount
  customerEmail = "example@test.com"
  request_opts = connected_account_request_opts
  begin
    list_q = { email: customerEmail, limit: 1 }
    log_stripe_request('lookupOrCreateExampleCustomer', 'Customer.list', list_q, request_opts)
    customerList = Stripe::Customer.list(list_q, request_opts).data
    if (customerList.length == 1)
      return customerList[0]
    else
      cp = { email: customerEmail }
      log_stripe_request('lookupOrCreateExampleCustomer', 'Customer.create', cp, request_opts)
      return Stripe::Customer.create(cp, request_opts)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("lookupOrCreateExampleCustomerOnConnectedAccount", "Creating or retrieving example customer", e)
  end
end

# This endpoint attaches a PaymentMethod to a Customer on the connected account.
# Only types such as generated_card (saved as type card) may be attached — not card_present.
# https://docs.stripe.com/terminal/features/saving-payment-details/save-after-payment
#
# Required params:
#   payment_method_id — reusable pm_... (e.g. from POST /retrieve_generated_card)
# Optional params:
#   customer_id       — attach to this specific customer (cus_...)
#   email             — if no customer_id, look up or create customer by email
post '/attach_payment_method_to_customer' do
  payment_method_id = params[:payment_method_id]
  if payment_method_id.nil? || payment_method_id.to_s.strip.empty?
    status 400
    return log_error("POST /attach_payment_method_to_customer", "'payment_method_id' is required")
  end

  begin
    ropts = connected_account_request_opts
    log_stripe_request('POST /attach_payment_method_to_customer', "PaymentMethod.retrieve(#{payment_method_id.strip})", {}, ropts)
    pm_check = Stripe::PaymentMethod.retrieve(payment_method_id.strip, ropts)
    log_info(
      "[STRIPE ← POST /attach_payment_method_to_customer] PaymentMethod.retrieve OK\n" \
      "id=#{pm_check.id} type=#{pm_check.type} customer=#{pm_check.customer}"
    )
    if pm_check.type.to_s == 'card_present'
      log_info(
        "[POST /attach_payment_method_to_customer] REJECTED card_present pm=#{pm_check.id}\n#{CARD_PRESENT_SAVE_ERROR_HINT}"
      )
      status 400
      content_type :json
      return {
        :error => 'card_present_not_attachable',
        :message => "PaymentMethods of type 'card_present' cannot be saved to customers. After a successful Terminal payment with setup_future_usage, call POST /retrieve_generated_card with the PaymentIntent id and use generated_card_payment_method_id for subscriptions or attach.",
      }.to_json
    end
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /attach_payment_method_to_customer", "Failed to verify PaymentMethod", e)
  end

  begin
    customer_id = params[:customer_id]
    if customer_id && !customer_id.to_s.strip.empty?
      customer_id = customer_id.strip
      log_info("[POST /attach_payment_method_to_customer] Using provided customer_id=#{customer_id}")
    else
      customer_email = params[:email] || params[:receipt_email]
      customer_id = lookupOrCreateCustomerOnConnectedAccount(customer_email)
      log_info("[POST /attach_payment_method_to_customer] Resolved customer_id=#{customer_id} from email")
    end

    attach_body = { customer: customer_id }
    log_stripe_request('POST /attach_payment_method_to_customer', "PaymentMethod.attach(#{payment_method_id})", attach_body, connected_account_request_opts)
    payment_method = Stripe::PaymentMethod.attach(
      payment_method_id,
      attach_body,
      connected_account_request_opts
    )
    log_info(
      "[STRIPE ← POST /attach_payment_method_to_customer] PaymentMethod.attach OK\n" \
      "id=#{payment_method.id} type=#{payment_method.type} customer=#{payment_method.customer}"
    )
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /attach_payment_method_to_customer", "Failed to attach PaymentMethod to Customer", e)
  end

  log_info("[POST /attach_payment_method_to_customer] Success: pm_id=#{payment_method_id} | customer_id=#{customer_id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")

  status 200
  content_type :json
  return { :payment_method => payment_method.id, :customer => customer_id }.to_json
end

# This endpoint updates the PaymentIntent on the connected account (e.g. receipt_email).
# https://stripe.com/docs/api/payment_intents/update
post '/update_payment_intent' do
  payment_intent_id = params["payment_intent_id"]
  if payment_intent_id.nil?
    status 400
    return log_error("POST /update_payment_intent", "'payment_intent_id' is a required parameter")
  end

  log_connect_context("POST /update_payment_intent", "Step: updating payment_intent_id=#{payment_intent_id}")

  begin
    allowed_keys = ["receipt_email"]
    update_params = params.select { |k, _| allowed_keys.include?(k) }
    ropts = connected_account_request_opts
    log_stripe_request('POST /update_payment_intent', "PaymentIntent.update(#{payment_intent_id})", update_params, ropts)
    payment_intent = Stripe::PaymentIntent.update(
      payment_intent_id,
      update_params,
      ropts
    )
    log_payment_intent_stripe_response('POST /update_payment_intent', 'PaymentIntent.update OK', payment_intent)

    log_info("Updated PaymentIntent #{payment_intent_id}")
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /update_payment_intent", "Failed to update PaymentIntent", e)
  end

  log_info("[POST /update_payment_intent] Success: payment_intent_id=#{payment_intent_id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# Creates an off-session recurring charge using a previously saved generated_card PaymentMethod.
# Use this instead of Stripe::Subscription for Terminal tap-to-pay recurring billing.
# The initial in-person payment is card_present, but recurring re-use is card-not-present
# using the generated_card PaymentMethod (type: card).
#
# Required params:
#   payment_method_id — the generated_card PaymentMethod ID (pm_..., type card)
#   customer_id       — the Stripe Customer ID (cus_...)
#   amount            — charge amount in cents
# Optional params:
#   currency          — defaults to 'usd'
#   description       — human-readable label for the charge
#   receipt_email     — email for the Stripe receipt
#   metadata          — hash of key/value pairs (e.g. order_id, subscription_id)
post '/create_recurring_payment' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_recurring_payment", validationError)
  end

  payment_method_id = params[:payment_method_id]
  customer_id       = params[:customer_id]
  amount            = params[:amount]

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

  log_connect_context("POST /create_recurring_payment", "Step: creating off-session PaymentIntent for saved generated_card")

  begin
    request_opts = connected_account_request_opts

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

    pi_params[:description]    = params[:description]   if params[:description]   && !params[:description].to_s.strip.empty?
    pi_params[:receipt_email]  = params[:receipt_email] if params[:receipt_email] && !params[:receipt_email].to_s.strip.empty?
    pi_params[:metadata]       = params[:metadata]      if params[:metadata]      && !params[:metadata].empty?

    log_stripe_request('POST /create_recurring_payment', 'PaymentIntent.create (off_session recurring)', pi_params, request_opts)
    payment_intent = Stripe::PaymentIntent.create(pi_params, request_opts)
    log_payment_intent_stripe_response('POST /create_recurring_payment', 'PaymentIntent.create OK', payment_intent)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_recurring_payment", "Failed to create off-session recurring PaymentIntent", e)
  end

  log_info("[POST /create_recurring_payment] Success: payment_intent_id=#{payment_intent.id} | customer_id=#{customer_id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  content_type :json
  return {
    :intent => payment_intent.id,
    :status => payment_intent.status,
    :amount => payment_intent.amount,
    :currency => payment_intent.currency,
  }.to_json
end

# Lists the first 100 Terminal locations on the connected account.
# https://stripe.com/docs/api/terminal/locations
get '/list_locations' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("GET /list_locations", validationError)
  end

  log_connect_context("GET /list_locations", "Step: listing locations")

  begin
    list_p = { limit: 100 }
    ropts = connected_account_request_opts
    log_stripe_request('GET /list_locations', 'Terminal::Location.list', list_p, ropts)
    locations = Stripe::Terminal::Location.list(list_p, ropts)
  rescue Stripe::StripeError => e
    status 402
    return log_error("GET /list_locations", "Failed to fetch Locations", e)
  end

  log_info("[GET /list_locations] Success: count=#{locations.data.size} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  content_type :json
  return locations.data.to_json
end

# Creates a Terminal location on the connected account.
# https://stripe.com/docs/api/terminal/locations
post '/create_location' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_error("POST /create_location", validationError)
  end

  log_connect_context("POST /create_location", "Step: creating location")

  begin
    location_params = {
      display_name: params[:display_name],
      address: params[:address]
    }
    ropts = connected_account_request_opts
    log_stripe_request('POST /create_location', 'Terminal::Location.create', location_params, ropts)
    location = Stripe::Terminal::Location.create(location_params, ropts)
  rescue Stripe::StripeError => e
    status 402
    return log_error("POST /create_location", "Failed to create Location", e)
  end

  log_info("[POST /create_location] Success: location_id=#{location.id} | stripe_account_id=#{CONNECTED_ACCOUNT_ID}")
  status 200
  content_type :json
  return location.to_json
end
