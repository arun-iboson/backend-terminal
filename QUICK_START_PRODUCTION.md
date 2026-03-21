# Quick Start: Production Deployment

## Required Environment Variables

You only need to set these 3 environment variables for production:

### 1. STRIPE_SECRET_KEY (REQUIRED)
**Purpose**: Stripe live mode payments  
**Format**: Must start with `sk_live_...`  
**Get it**: https://dashboard.stripe.com/account/apikeys

### 2. ENVIRONMENT (REQUIRED)
**Purpose**: Enables production mode  
**Value**: `production`

### 3. STRIPE_ENV (REQUIRED)
**Purpose**: Uses live Stripe keys  
**Value**: `production`

## Quick Setup Example

### For Render.com or Heroku:
```bash
ENVIRONMENT=production
STRIPE_ENV=production
RACK_ENV=production
STRIPE_SECRET_KEY=sk_live_YOUR_LIVE_KEY_HERE
```

### For Docker:
```bash
docker run -d \
  -p 4567:4567 \
  -e ENVIRONMENT=production \
  -e STRIPE_ENV=production \
  -e STRIPE_SECRET_KEY=sk_live_... \
  your-image-name
```

## What Happens If You Skip One?

| Variable | If Missing | Result |
|----------|-----------|--------|
| `STRIPE_SECRET_KEY` | ⚠️ Warning logged | **Stripe won't work** |
| `ENVIRONMENT` | ⚠️ Runs in test mode | **Wrong Stripe keys used** |
| `STRIPE_ENV` | ⚠️ May use test keys | **Wrong Stripe keys used** |

## Summary

**You only need the Stripe production secret key!** That's it.

The server will check on startup and warn you if the Stripe key is missing or invalid.
