import ipaddress

import httpx

from app.core.config import (
    VIRUSTOTAL_API_KEY,
    ABUSEIPDB_API_KEY,
)


async def query_virustotal(
    indicator: str,
) -> dict:

    if not VIRUSTOTAL_API_KEY:
        return {
            "source": "virustotal",
            "available": False,
            "reason": "API key not configured",
        }

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    params = {
        "query": indicator,
    }

    async with httpx.AsyncClient(
        timeout=20
    ) as client:

        response = await client.get(
            "https://www.virustotal.com/api/v3/search",
            params=params,
            headers=headers,
        )

    if response.status_code != 200:
        return {
            "source": "virustotal",
            "available": False,
            "status_code": response.status_code,
        }

    payload = response.json()

    data = payload.get("data", [])

    score = None
    verdict = "unknown"

    if data:
        attributes = (
            data[0].get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious = stats.get(
            "malicious",
            0,
        )

        suspicious = stats.get(
            "suspicious",
            0,
        )

        harmless = stats.get(
            "harmless",
            0,
        )

        undetected = stats.get(
            "undetected",
            0,
        )

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
        )

        if total:
            score = (
                (
                    malicious
                    + suspicious * 0.5
                )
                / total
            ) * 100

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

    return {
        "source": "virustotal",
        "available": True,
        "verdict": verdict,
        "confidence": round(score, 2)
        if score is not None
        else None,
        "summary": (
            f"VirusTotal returned "
            f"{len(data)} matching object(s)."
        ),
        "raw_data": {
            "matches": data[:3],
        },
    }


async def query_abuseipdb(
    indicator: str,
) -> dict:

    if not ABUSEIPDB_API_KEY:
        return {
            "source": "abuseipdb",
            "available": False,
            "reason": "API key not configured",
        }

    try:
        ipaddress.ip_address(indicator)
    except ValueError:
        return {
            "source": "abuseipdb",
            "available": False,
            "reason": "Indicator is not an IP address",
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": indicator,
        "maxAgeInDays": 90,
    }

    async with httpx.AsyncClient(
        timeout=20
    ) as client:

        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params=params,
            headers=headers,
        )

    if response.status_code != 200:
        return {
            "source": "abuseipdb",
            "available": False,
            "status_code": response.status_code,
        }

    payload = response.json()

    data = payload.get(
        "data",
        {},
    )

    confidence = data.get(
        "abuseConfidenceScore"
    )

    if confidence is None:
        verdict = "unknown"
    elif confidence >= 70:
        verdict = "malicious"
    elif confidence >= 30:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "source": "abuseipdb",
        "available": True,
        "verdict": verdict,
        "confidence": confidence,
        "summary": (
            f"AbuseIPDB abuse confidence "
            f"score: {confidence}."
        ),
        "raw_data": {
            "country": data.get(
                "countryCode"
            ),
            "isp": data.get("isp"),
            "domain": data.get(
                "domain"
            ),
            "total_reports": data.get(
                "totalReports"
            ),
            "usage_type": data.get(
                "usageType"
            ),
        },
    }


async def lookup_indicator(
    indicator: str,
    indicator_type: str,
) -> list[dict]:

    results = []

    vt = await query_virustotal(
        indicator
    )

    if vt.get("available"):
        results.append(vt)

    if indicator_type == "ip":

        abuse = await query_abuseipdb(
            indicator
        )

        if abuse.get("available"):
            results.append(abuse)

    return results