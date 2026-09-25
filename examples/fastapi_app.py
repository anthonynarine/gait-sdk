"""The smallest useful FastAPI app protected by gait-sdk.

Run it (three terminals, from this examples/ folder):

    pip install "gait-sdk[fastapi]" uvicorn
    python dev_issuer.py serve                                    # 1. a local stand-in for Gait
    GAIT_TOKEN_VERIFIER=jwks \\
    GAIT_JWKS_URL=http://localhost:9000/.well-known/jwks.json \\
    GAIT_ISSUER=http://localhost:9000 GAIT_AUDIENCE=urn:gait:example \\
    uvicorn fastapi_app:app --port 8001                           # 2. this app
    curl -H "Authorization: Bearer $(python dev_issuer.py token alice)" \\
         http://localhost:8001/me                                 # 3. call it

(Windows PowerShell: set each variable with $env:NAME = "value" first.)
"""

from fastapi import Depends, FastAPI, HTTPException, Request

from gait_sdk.fastapi.dependencies import validate_configuration, verify_token

app = FastAPI(title="gait-sdk example")
validate_configuration()  # misconfiguration fails here, at startup -- not on the first request

# Your app owns authorization. Here it's a toy in-memory table keyed by the
# Gait subject; in a real app this is your database (memberships, roles...).
ROLES = {"alice": "editor", "bob": "viewer"}


@app.get("/me")
async def me(request: Request, claims: dict = Depends(verify_token)):
    identity = request.state.verified_identity  # gait-sdk: WHO this is
    return {
        "subject": identity.subject,
        "email": identity.email,
        "session_id": identity.session_id,
        "your_app_role": ROLES.get(identity.subject, "none"),  # your app: WHAT they may do
    }


@app.post("/articles")
async def create_article(request: Request, claims: dict = Depends(verify_token)):
    subject = request.state.verified_identity.subject
    if ROLES.get(subject) != "editor":  # authorization is YOUR decision
        raise HTTPException(status_code=403, detail="Editors only.")
    return {"created_by": subject}
