"""
Test script to verify Gemini API is working for agent discussion generation
"""
import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.gemini_service import GeminiService, GeminiServiceError
from app.config import settings

async def test_gemini_discussion():
    """Test Gemini agent discussion generation"""
    print("=" * 60)
    print("Testing Gemini Agent Discussion Generation")
    print("=" * 60)
    
    # Check if API key is configured
    if not settings.gemini_api_key or settings.gemini_api_key == "":
        print("❌ GEMINI_API_KEY not configured in .env")
        return False
    
    print(f"✓ GEMINI_API_KEY is configured (length: {len(settings.gemini_api_key)})")
    print(f"✓ Using model: {settings.gemini_model}")
    print()
    
    # Initialize service
    gemini = GeminiService()
    
    # Test cases
    test_cases = [
        "Ransomware Campaign - LockBit 3.0",
        "Phishing Attack on Finance Department",
        "Unpatched VPN Gateway CVE-2024-1234"
    ]
    
    for i, risk_title in enumerate(test_cases, 1):
        print(f"\n[Test {i}] Risk: {risk_title}")
        print("-" * 60)
        
        try:
            discussion = await gemini.generate_agent_discussion(
                risk_title=risk_title,
                agents=["analyst", "intel", "forensics", "business"],
                max_messages=6
            )
            
            print(f"✓ Success! Generated {len(discussion)} messages")
            print()
            
            for msg in discussion:
                agent = msg.get("agent", "unknown")
                message = msg.get("message", "")
                offset = msg.get("timestamp_offset_seconds", 0)
                
                # Truncate message for display
                display_msg = message[:80] + "..." if len(message) > 80 else message
                print(f"  [{agent:10s}] +{offset:3d}s | {display_msg}")
            
        except GeminiServiceError as e:
            print(f"❌ Gemini Error: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    print("\n" + "=" * 60)
    print("✓ All tests passed! Gemini API is working correctly.")
    print("=" * 60)
    return True

if __name__ == "__main__":
    result = asyncio.run(test_gemini_discussion())
    sys.exit(0 if result else 1)
