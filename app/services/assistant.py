from ..schemas.common import AssistantResponse

def answer(message:str, context:dict|None=None)->AssistantResponse:
    m=message.lower(); actions=[]
    if any(x in m for x in ["api key","secret","token","password"]):
        text="Treat exposed credentials as compromised: revoke or rotate them, remove them from source control, and move them to environment variables or a secrets manager. Sentinel's static scanner flags credential-like patterns but cannot prove whether a value is valid."
        actions=["Rotate/revoke the credential","Remove it from Git history if it was committed","Store secrets outside source control"]
    elif "phishing" in m or "url" in m:
        text="Phishing assessment should combine URL structure, redirects, TLS, page behavior, domain reputation, and user context. Sentinel's current URL scanner performs heuristic checks and does not provide a definitive reputation verdict."
        actions=["Verify the domain independently","Do not enter credentials on an untrusted page","Use a threat-intelligence feed for stronger reputation checks"]
    elif "vulnerability" in m or "cve" in m:
        text="A vulnerability finding should be triaged by severity, affected component/version, exploitability, exposure, and available remediation. Sentinel can report static findings, while dependency/CVE enrichment should be added through a trusted advisory source."
        actions=["Identify the affected dependency/version","Check the vendor advisory","Patch and retest"]
    else:
        text="I can help interpret Sentinel findings, explain common web/code-security risks, and suggest remediation. Include the scan result or finding you want analyzed for a more specific answer."
    return AssistantResponse(answer=text,suggested_actions=actions)
