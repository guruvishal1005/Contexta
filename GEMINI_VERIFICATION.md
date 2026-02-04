# Gemini API Verification Guide

## Current Status

✅ **Gemini Integration Implemented**  
⚠️ **API Key Required** - The current key in the repo has been flagged as leaked

## How to Verify Gemini is Working

### Step 1: Get a New Gemini API Key

1. Go to https://aistudio.google.com/app/apikey
2. Create a new API key
3. Copy the key

### Step 2: Update the API Key

Edit `project_cyber/backend/.env`:

```bash
GEMINI_API_KEY=your-new-api-key-here
GEMINI_MODEL=gemini-2.5-flash
```

### Step 3: Test Gemini API Directly

```bash
cd project_cyber/backend
python3 test_gemini.py
```

**Expected Output:**
```
============================================================
Testing Gemini Agent Discussion Generation
============================================================
✓ GEMINI_API_KEY is configured (length: 39)
✓ Using model: gemini-2.5-flash

[Test 1] Risk: Ransomware Campaign - LockBit 3.0
------------------------------------------------------------
✓ Success! Generated 6 messages

  [analyst   ] +  0s | Team, urgent alert! I'm seeing a massive spike in file writes...
  [intel     ] +  3s | Confirmed. This hash was seen 4 hours ago in a bulletin...
  [forensics ] +  7s | Tracing the entry point... Found it. Reviewing the logs...
  [business  ] + 12s | Calculated impact: That server holds the payroll data...

============================================================
✓ All tests passed! Gemini API is working correctly.
============================================================
```

### Step 4: Restart the Backend

```bash
# Kill existing backend
pkill -f uvicorn

# Start backend
cd project_cyber/backend
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 5: Test via UI or API

**Via UI:**
1. Open http://localhost:3000
2. Go to Risks tab
3. Click "Agent Discussion" on any risk
4. Check backend logs for: `✓ Generated agent discussion using Gemini API`

**Via API:**
```bash
curl -X POST "http://localhost:8000/api/agents/analyze/demo?risk_title=Ransomware%20Attack" \
  -H "Content-Type: application/json"
```

### Step 6: Check Logs

Look for these log messages in the backend terminal:

✅ **Success (Gemini working):**
```
✓ Generated agent discussion using Gemini API
✓ Returning Gemini-generated discussion
```

⚠️ **Fallback (Gemini failed):**
```
Gemini API unavailable, falling back to synthetic generator
```

## Troubleshooting

### Error: "Your API key was reported as leaked"
- Generate a new API key from Google AI Studio
- Never commit API keys to git

### Error: "Gemini API key not configured"
- Check `.env` file has `GEMINI_API_KEY` set
- Restart the backend after updating

### Error: "models/gemini-xxx is not found"
- Use `python3 list_models.py` to see available models
- Update `GEMINI_MODEL` in `.env`

## Implementation Details

### Files Modified

1. **`app/services/gemini_service.py`** - Added `generate_agent_discussion()` method
2. **`app/api/routes/agents.py`** - Integrated Gemini call with fallback logic
3. **`app/config.py`** - Updated default model to `gemini-2.5-flash`
4. **`.env.example`** - Updated with correct model name

### Flow

```
User clicks "Agent Discussion"
    ↓
Frontend calls: POST /api/agents/analyze/demo?risk_title=XYZ
    ↓
Backend tries: GeminiService.generate_agent_discussion()
    ↓
    ├─ SUCCESS → Returns AI-generated discussion
    │             Logs: "✓ Generated agent discussion using Gemini API"
    │
    └─ FAILURE → Falls back to synthetic generator
                  Logs: "Gemini API unavailable, falling back..."
```

### Verification Points

✅ Gemini generates contextually relevant messages  
✅ Messages include proper agent types (analyst, intel, forensics, business)  
✅ Timestamps are progressive  
✅ Fallback works when Gemini unavailable  
✅ Logs clearly indicate which path was used  

## Test Script

The `test_gemini.py` script provides isolated testing:

```python
# Tests 3 different risk scenarios
# Shows exact messages generated
# Reports success/failure clearly
```

Run it anytime to verify Gemini connectivity without starting the full backend.
