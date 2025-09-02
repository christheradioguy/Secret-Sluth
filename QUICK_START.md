# Quick Start Guide - Test Secret Sluth in Your Browser

This guide will help you quickly set up and test the Secret Sluth application with a real Vault server.

## 🚀 Quick Setup (5 minutes)

### Step 1: Start a Test Vault Server

**Option A: Using Docker (Recommended)**
```bash
# Start Vault in development mode
docker run -d \
  --name vault-test \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=test-token \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  vault:latest
```

**Option B: Using Vault CLI**
```bash
# Install Vault CLI first, then run:
vault server -dev -dev-root-token-id=test-token -dev-listen-address=0.0.0.0:8200
```

### Step 2: Create Test Data

1. **Open Vault UI**: http://localhost:8200
2. **Login with token**: `test-token`
3. **Enable KV engine**: Go to "Secrets" → "Enable new engine" → Select "KV" → Path: `secret`
4. **Create test secrets**:
   - Path: `app/database` → Add keys: `username=admin`, `password=secret123`
   - Path: `api/credentials` → Add keys: `api_key=abc123`, `password=xyz789`

### Step 3: Start Secret Sluth

```bash
# In your project directory
python run.py
```

### Step 4: Test in Browser

1. **Open**: http://localhost:5000
2. **Connect to Vault**:
   - URL: `http://localhost:8200`
   - Token: `test-token`
3. **Test features**:
   - Click "Test Connection"
   - Try "List Secret Engines"
   - View "Token Details"

## 🎯 What You'll See

### Home Page
- Beautiful landing page with connection options
- Modern UI with gradient background
- Responsive design

### Connection Form
- Clean form for Vault URL and token
- Helpful instructions and security notes
- Proper validation and error handling

### Dashboard
- Connection status with green indicator
- Token information display
- Quick action buttons
- Real-time results area

### Features Working
✅ **Connection Management**: Connect/disconnect to Vault  
✅ **Token Validation**: Verify token and show details  
✅ **Secret Engine Discovery**: List available engines  
✅ **Real-time Testing**: Test connection via AJAX  
✅ **Session Management**: Secure session handling  
✅ **Error Handling**: Graceful error display  

## 🔍 Testing Scenarios

### Happy Path
1. Connect with valid credentials
2. Test connection → See secret engines
3. View token details → See policies and TTL
4. Disconnect → Session cleared

### Error Scenarios
1. **Invalid URL**: Try `http://invalid-url:8200`
2. **Invalid Token**: Try `invalid-token`
3. **Wrong Protocol**: Try `https://localhost:8200` (should auto-correct)

## 🛠️ Development Features

### Hot Reload
- Flask debug mode enabled
- Auto-reload on code changes
- Live error display

### Logging
- Structured logging with timestamps
- Debug information in console
- Error tracking

### Security
- Session-based authentication
- Secure cookie handling
- Token never logged or displayed

## 📱 Browser Compatibility

- ✅ Chrome/Chromium
- ✅ Firefox
- ✅ Safari
- ✅ Edge
- ✅ Mobile responsive

## 🔧 Customization

### Environment Variables
```bash
export FLASK_ENV=development
export FLASK_DEBUG=1
export SECRET_KEY=your-secret-key
```

### Configuration
Edit `app/config.py` for:
- Session timeout
- Logging levels
- Security settings

## 🚨 Troubleshooting

### Common Issues

**"Connection failed"**
- Check if Vault is running on port 8200
- Verify URL: `http://localhost:8200`
- Ensure token is correct: `test-token`

**"Template not found"**
- Check if templates are in correct location
- Verify Flask app structure

**"Import error"**
- Activate virtual environment
- Install dependencies: `pip install -r requirements.txt`

### Debug Mode
The app runs in debug mode, so you'll see:
- Detailed error messages
- Auto-reload on changes
- Debug toolbar (if installed)

## 🎉 Success!

Once you see:
- ✅ Connected status indicator
- ✅ Secret engines listed
- ✅ Token details displayed
- ✅ No errors in browser console

You've successfully tested the Secret Sluth application! 

## 📋 Next Steps

1. **Try the search functionality** (coming in next step)
2. **Add more test secrets** to explore
3. **Test with production Vault** (with proper policies)
4. **Continue with implementation plan**

---

**Need help?** Check the full documentation in `docs/testing-setup.md` or create an issue in the repository.
