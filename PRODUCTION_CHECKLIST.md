# Production Deployment Checklist

Use this checklist before deploying to production to ensure all security measures are in place.

## Pre-Deployment Configuration

### Environment Variables (Required)

- [ ] **`STRIPE_SECRET_KEY`** - Your Stripe **LIVE** secret key
  - Must start with `sk_live_...`
  - Get from: https://dashboard.stripe.com/account/apikeys
  - **Never commit to version control**

- [ ] **`ALLOWED_ORIGINS`** - Comma-separated list of allowed origins
  - Example: `https://yourdomain.com,https://app.yourdomain.com`
  - **Must NOT include `*` in production**
  - Include all domains that will make requests to the API

- [ ] **`ENVIRONMENT`** or **`RACK_ENV`** - Set to `production`

- [ ] **`STRIPE_ENV`** - Set to `production`

### Security Verification

- [ ] HTTPS is enabled (handled by hosting provider)
- [ ] All Stripe keys are stored in environment variables (not in code)
- [ ] `.env` file is in `.gitignore` (if using git)
- [ ] Stripe dashboard is monitored for unusual activity

### Testing Checklist

- [ ] Test `/connection_token` endpoint
- [ ] Test `/create_payment_intent` endpoint
- [ ] Test CORS from your frontend domain (should work from any origin)
- [ ] Verify live Stripe keys are being used
- [ ] Test a small live payment (verify it appears in Stripe dashboard)

### Deployment Platform Configuration

#### Render.com
- [ ] Environment variables set in Render dashboard
- [ ] Service plan is appropriate (not free tier for production)
- [ ] Auto-deploy is configured correctly
- [ ] Health checks are working

#### Heroku
- [ ] Environment variables set via `heroku config:set`
- [ ] Dyno type is appropriate (not free tier for production)
- [ ] SSL is enabled (automatic on Heroku)
- [ ] App is not sleeping (consider paid dyno)

#### Docker
- [ ] Docker image is built correctly
- [ ] Environment variables are passed to container
- [ ] Container exposes correct port
- [ ] Container is behind reverse proxy with HTTPS

### Post-Deployment

- [ ] Verify server starts without errors
- [ ] Check server logs for warnings
- [ ] Test API endpoints from production URL
- [ ] Monitor error rates in first 24 hours
- [ ] Set up logging/alerting for errors
- [ ] Document API key rotation process

## Common Issues

### CORS errors from frontend
**Solution**: 
1. CORS is enabled for all origins by default
2. Ensure frontend sends requests with proper Origin header
3. Check that CORS preflight (OPTIONS) requests are working

### "Invalid Stripe key" errors
**Solution**: 
1. Verify `STRIPE_SECRET_KEY` is set (for production)
2. Ensure key starts with `sk_live_...`
3. Check key is not expired/revoked in Stripe dashboard

### Authentication failing
**Solution**:
1. Verify API key matches between backend and client
2. Check that client sends key in `X-API-Key` header or `Authorization: Bearer` header
3. Ensure no extra spaces in API key value

## Security Best Practices

1. **Rotate API keys regularly** (every 90 days recommended)
2. **Use different API keys** for different environments (dev/staging/prod)
3. **Monitor Stripe dashboard** for unusual payment activity
4. **Set up webhooks** for payment status updates (recommended)
5. **Enable Stripe Radar** for fraud prevention
6. **Review access logs** regularly
7. **Keep dependencies updated** (`bundle update` regularly)
8. **Use HTTPS everywhere** (never HTTP in production)

## Support

If you encounter issues:
1. Check server logs for detailed error messages
2. Verify all environment variables are set correctly
3. Test endpoints with `curl` to isolate issues
4. Check Stripe dashboard for API errors
5. Review the README.md for detailed documentation
