/**
 * verify_frontend.js
 * 
 * 이 스크립트는 현재 실행 중인 프론트엔드 서버(http://localhost:3000)로부터
 * HTML을 가져와서 NetAlly 프로젝트의 코드가 맞는지 검증합니다.
 */

async function verify() {
  const url = 'http://localhost:3000/';
  console.log(`Checking ${url}...`);

  try {
    const response = await fetch(url);
    const text = await response.text();

    console.log("--- Header Info ---");
    console.log(`Status: ${response.status}`);
    console.log(`Content-Type: ${response.headers.get('content-type')}`);
    
    console.log("\n--- Content Check ---");
    const hasNetAllyTitle = text.includes('<title>NetAlly');
    const hasMainTsx = text.includes('src="/src/main.tsx"');
    const hasCreateReactAppStuff = text.includes('/static/js/main.js') || text.includes('body_with_background');

    if (hasNetAllyTitle && hasMainTsx) {
      console.log("✅ Success: The server IS serving the NetAlly project correctly.");
    } else {
      console.log("❌ Error: The server is NOT serving NetAlly content.");
    }

    if (hasCreateReactAppStuff) {
      console.log("⚠️ Warning: Detected traces of another React app (CRA).");
    }

    console.log("\n--- Raw HTML Snippet ---");
    console.log(text.substring(0, 500) + "...");

  } catch (error) {
    console.error("❌ Failed to connect to the frontend server:", error.message);
  }
}

verify();
