/**
 * PNETLab 쿠키 추출 스크립트 (개선 버전)
 * 
 * 사용법:
 * 1. PNETLab 웹사이트에서 F12 (개발자도구) 열기
 * 2. Network 탭으로 이동
 * 3. 아무 요청(request) 클릭
 * 4. Headers 탭에서 "Request Headers" 섹션 찾기
 * 5. "Cookie:" 값 전체를 복사
 * 6. 아래 방법 2 사용!
 * 
 * ============================================================
 * ⚠️  PNETLab 쿠키는 HttpOnly로 설정되어 JavaScript로 접근 불가!
 * 대신 아래 방법을 사용하세요:
 * ============================================================
 */

console.log('\n' + '='.repeat(60));
console.log('📋 PNETLab 쿠키 가져오는 방법');
console.log('='.repeat(60));
console.log('');
console.log('🚫 JavaScript로 쿠키 접근 불가 (HttpOnly 설정됨)');
console.log('');
console.log('✅ 대신 이렇게 하세요:');
console.log('');
console.log('1. F12 → Network 탭');
console.log('2. 아무 요청 클릭 (예: topology, nodestatus 등)');
console.log('3. Headers 탭 → Request Headers → Cookie 값 복사');
console.log('');
console.log('예시:');
console.log('Cookie: token=eyJ...; _session=eyJ...; XSRF-TOKEN=eyJ...');
console.log('');
console.log('4. .env 파일에 다음과 같이 입력:');
console.log('');
console.log('PNETLAB_COOKIES=위에서_복사한_전체_문자열');
console.log('');
console.log('='.repeat(60));
console.log('');
console.log('또는 개별로 복사하려면:');
console.log('');
console.log('1. F12 → Application → Cookies → http://100.66.240.82');
console.log('2. token, _session, XSRF-TOKEN 값을 각각 복사');
console.log('3. .env 파일에:');
console.log('   PNETLAB_JWT_TOKEN=...');
console.log('   PNETLAB_SESSION=...');
console.log('   PNETLAB_XSRF_TOKEN=...');
console.log('');
console.log('='.repeat(60));

