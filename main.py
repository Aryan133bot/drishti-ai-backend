from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import AzureOpenAI
import os
import re
from typing import Optional

app = FastAPI(title="DRISHTI.AI API", version="1.0.0")
@app.get("/")
def root():
    return {"status": "DRISHTI.AI backend is running"}


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Azure OpenAI Configuration
# Set these environment variables or replace with your values
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "https://your-resource.openai.azure.com/")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY", "your-api-key-here")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")

 Initialize Azure OpenAI client
 try:
     client = AzureOpenAI(
         azure_endpoint=AZURE_OPENAI_ENDPOINT,
         api_key=AZURE_OPENAI_API_KEY,
         api_version=AZURE_OPENAI_API_VERSION
     )
 except Exception as e:
     print(e)
     client = None



class MessageRequest(BaseModel):
    message: str


class AnalysisResponse(BaseModel):
    risk_level: str  # "Low", "Medium", "High"
    confidence: float  # 0.0 to 1.0
    explanation: str
    indicators: list[str]
    safety_tips: list[str]
    message_preview: str


def detect_scam_patterns(message: str) -> dict:
    """
    Rule-based pattern detection for common scam indicators
    """
    message_lower = message.lower()
    indicators = []
    risk_score = 0
    
    # Urgency patterns
    urgency_keywords = [
        "urgent", "immediately", "act now", "limited time", 
        "expire", "suspended", "blocked", "verify now"
    ]
    if any(keyword in message_lower for keyword in urgency_keywords):
        indicators.append("Contains urgency language")
        risk_score += 2
    
    # Request for sensitive information
    sensitive_keywords = [
        "password", "pin", "otp", "cvv", "credit card", 
        "bank account", "social security", "ssn", "verification code"
    ]
    if any(keyword in message_lower for keyword in sensitive_keywords):
        indicators.append("Requests sensitive information")
        risk_score += 3
    
    # Financial threats or promises
    financial_keywords = [
        "refund", "prize", "won", "lottery", "inheritance", 
        "millions", "tax", "payment failed", "debt"
    ]
    if any(keyword in message_lower for keyword in financial_keywords):
        indicators.append("Contains financial promises or threats")
        risk_score += 2
    
    # Links (basic detection)
    if re.search(r'http[s]?://|www\.|\.[a-z]{2,}/', message_lower):
        indicators.append("Contains links")
        risk_score += 1
        
        # Suspicious link patterns
        suspicious_domains = ["bit.ly", "tinyurl", "shorturl", "suspicious"]
        if any(domain in message_lower for domain in suspicious_domains):
            indicators.append("Contains shortened or suspicious links")
            risk_score += 2
    
    # Impersonation patterns
    impersonation_keywords = [
        "amazon", "paypal", "netflix", "bank", "irs", 
        "government", "police", "customer support", "tech support"
    ]
    if any(keyword in message_lower for keyword in impersonation_keywords):
        indicators.append("May be impersonating legitimate organization")
        risk_score += 2
    
    # Poor grammar/spelling (basic check)
    grammar_issues = ["dear customer", "kindly", "needful", "revert back"]
    if any(phrase in message_lower for phrase in grammar_issues):
        indicators.append("Contains unusual phrasing")
        risk_score += 1
    
    # Threats
    threat_keywords = ["legal action", "arrest", "lawsuit", "police", "court"]
    if any(keyword in message_lower for keyword in threat_keywords):
        indicators.append("Contains threatening language")
        risk_score += 3
    
    return {
        "indicators": indicators,
        "risk_score": risk_score
    }


def get_safety_tips(risk_level: str) -> list[str]:
    """
    Provide contextual safety tips based on risk level
    """
    base_tips = [
        "Never share passwords, OTPs, or PINs with anyone",
        "Verify sender identity through official channels",
        "Be cautious of urgent requests or threats"
    ]
    
    if risk_level == "High":
        return base_tips + [
            "Do NOT click any links in this message",
            "Do NOT respond to this message",
            "Report this message to relevant authorities",
            "Block the sender immediately"
        ]
    elif risk_level == "Medium":
        return base_tips + [
            "Verify the message through official channels before taking action",
            "Look for official contact information independently",
            "Be cautious of any links or attachments"
        ]
    else:
        return base_tips + [
            "Stay vigilant for similar messages",
            "When in doubt, verify independently"
        ]


async def analyze_with_ai(message: str) -> dict:
    """
    Use Azure OpenAI to analyze the message for scam/phishing indicators
    """
    if not client:
        raise HTTPException(
            status_code=500, 
            detail="Azure OpenAI service not configured"
        )
    
    system_prompt = """You are DRISHTI.AI, an expert scam and phishing detection system. 
Analyze messages for scam indicators and provide a risk assessment.

Provide your analysis in this exact JSON format:
{
    "risk_level": "Low|Medium|High",
    "confidence": 0.0-1.0,
    "explanation": "Brief explanation in 2-3 sentences",
    "key_indicators": ["indicator1", "indicator2"]
}

Consider:
- Urgency tactics
- Requests for sensitive information
- Impersonation attempts
- Suspicious links
- Threats or fear tactics
- Too-good-to-be-true offers
- Poor grammar/spelling
- Generic greetings

Be helpful and clear. Focus on user safety."""

    try:
        response = client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this message:\n\n{message}"}
            ],
            temperature=0.3,
            max_tokens=500
        )
        
        ai_response = response.choices[0].message.content
        
        # Parse AI response (basic JSON extraction)
        import json
        # Try to extract JSON from response
        try:
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                ai_analysis = json.loads(json_match.group())
            else:
                # Fallback parsing
                ai_analysis = {
                    "risk_level": "Medium",
                    "confidence": 0.7,
                    "explanation": ai_response[:200],
                    "key_indicators": []
                }
        except:
            ai_analysis = {
                "risk_level": "Medium",
                "confidence": 0.7,
                "explanation": ai_response[:200],
                "key_indicators": []
            }
        
        return ai_analysis
        
    except Exception as e:
        print(f"Azure OpenAI error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"AI analysis failed: {str(e)}"
        )


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "DRISHTI.AI API",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "azure_openai_configured": client is not None
    }


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_message(request: MessageRequest):
    """
    Main endpoint to analyze a message for scam/phishing indicators
    """
    message = request.message.strip()
    
    # Validation
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    if len(message) > 5000:
        raise HTTPException(
            status_code=400, 
            detail="Message too long (max 5000 characters)"
        )
    
    # Rule-based pattern detection
    pattern_analysis = detect_scam_patterns(message)
    
    # AI analysis
    try:
        ai_analysis = await analyze_with_ai(message)
    except HTTPException:
        # Fallback to rule-based only if AI fails
        risk_score = pattern_analysis["risk_score"]
        if risk_score >= 6:
            risk_level = "High"
            confidence = 0.8
        elif risk_score >= 3:
            risk_level = "Medium"
            confidence = 0.7
        else:
            risk_level = "Low"
            confidence = 0.6
        
        ai_analysis = {
            "risk_level": risk_level,
            "confidence": confidence,
            "explanation": "Analysis based on detected scam patterns.",
            "key_indicators": []
        }
    
    # Combine indicators
    all_indicators = list(set(
        pattern_analysis["indicators"] + 
        ai_analysis.get("key_indicators", [])
    ))
    
    # If no indicators found
    if not all_indicators:
        all_indicators = ["No obvious scam indicators detected"]
    
    # Get risk level from AI (or fallback)
    risk_level = ai_analysis.get("risk_level", "Medium")
    confidence = ai_analysis.get("confidence", 0.7)
    explanation = ai_analysis.get("explanation", "Message analyzed for common scam patterns.")
    
    # Get contextual safety tips
    safety_tips = get_safety_tips(risk_level)
    
    # Create message preview
    message_preview = message[:100] + "..." if len(message) > 100 else message
    
    return AnalysisResponse(
        risk_level=risk_level,
        confidence=confidence,
        explanation=explanation,
        indicators=all_indicators[:5],  # Limit to top 5
        safety_tips=safety_tips[:4],    # Limit to 4 tips
        message_preview=message_preview
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
