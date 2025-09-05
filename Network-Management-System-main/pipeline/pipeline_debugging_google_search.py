# pip install requests requests-cache trafilatura pdfminer.six
import os, io, time, urllib.parse, requests, requests_cache
from typing import List, Dict, Optional
os.environ["GOOGLE_CSE_ID"] = "API_key"
os.environ["GOOGLE_API_KEY"] = "API_key"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36"
requests_cache.install_cache("cse_cache", expire_after=60*10)

def cse_search(query: str, num: int = 10, start: int = 1,
               site: Optional[str] = None, file_type: Optional[str] = None) -> List[Dict]:
    key = os.environ.get("GOOGLE_API_KEY")
    cx  = os.environ.get("GOOGLE_CSE_ID")
    if not key:  raise RuntimeError("GOOGLE_API_KEY not set")
    if not cx:   raise RuntimeError("GOOGLE_CSE_ID not set")

    q = query if not site else f'{query} site:{site}'
    params = {"q": q, "key": key, "cx": cx, "num": min(num, 10), "start": start}
    if file_type: params["fileType"] = file_type

    r = requests.get("https://www.googleapis.com/customsearch/v1",
                     params=params, headers={"User-Agent": UA}, timeout=20)
    r.raise_for_status()
    data = r.json()
    return data.get("items", []) or []

def _extract_html(content: bytes, url: str) -> str:
    # 1st: trafilatura (본문 추출 강함), 2nd: 단순 텍스트
    import trafilatura
    downloaded = trafilatura.extract(content, url=url, include_comments=False, include_tables=False)  # type: ignore
    if downloaded: return downloaded
    # fallback
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(content, "html.parser")
    for s in soup(["script","style","noscript"]): s.decompose()
    return soup.get_text(" ", strip=True)

def fetch_content(url: str, max_retries: int = 3, sleep_base: float = 1.0) -> str:
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers={"User-Agent": UA}, timeout=30)
            if resp.status_code in (429, 503):
                time.sleep(sleep_base * (2 ** attempt)); continue
            resp.raise_for_status()
            ctype = resp.headers.get("Content-Type","").lower()
            if "application/pdf" in ctype or url.lower().endswith(".pdf"):
                return _extract_pdf(resp.content)
            return _extract_html(resp.content, url)
        except Exception as e:
            if attempt == max_retries-1: raise
            time.sleep(sleep_base * (2 ** attempt))
    return ""

def search_and_extract(query: str,
                       top_k: int = 5,
                       domain_whitelist: Optional[List[str]] = None) -> List[Dict]:
    items = cse_search(query, num=10)
    results = []
    for it in items:
        link = it.get("link")
        title = it.get("title","")
        display = it.get("displayLink","").lower()
        if domain_whitelist and not any(d in display for d in domain_whitelist):
            continue
        try:
            text = fetch_content(link)
            results.append({
                "title": title,
                "link": link,
                "snippet": it.get("snippet",""),
                "content": text
            })
        except Exception as e:
            results.append({
                "title": title,
                "link": link,
                "snippet": it.get("snippet",""),
                "error": str(e)
            })
        if len(results) >= top_k: break
    return results

if __name__ == "__main__":
    query = "Cisco IOS interface configuration best practices vlan vrf ipv4"
    out = search_and_extract(query, top_k=1, domain_whitelist=["cisco.com","ciscolive.com"])
    print(f"Fetched {len(out)} docs")
    print(out[0]["title"], out[0]["link"])
    print(out[0]["content"])
