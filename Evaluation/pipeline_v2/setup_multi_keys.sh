#!/bin/bash
# 다중 API 키 설정 헬퍼 스크립트
# Usage: ./setup_multi_keys.sh [key1] [key2] [key3] ...

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔑 다중 OpenAI API 키 설정 도구${NC}"
echo "=================================="

# 인자로 받은 키들 설정
if [ $# -gt 0 ]; then
    echo -e "${GREEN}📥 전달받은 API 키들을 설정합니다...${NC}"
    for i in $(seq 1 $#); do
        key_var="OPENAI_API_KEY_$i"
        key_value="${!i}"
        export $key_var="$key_value"
        echo -e "✅ $key_var: 설정됨 (${key_value:0:10}...)"
    done
    echo ""
else
    # 대화형 모드
    echo -e "${YELLOW}📝 대화형 모드: API 키를 차례로 입력하세요 (빈 입력시 종료)${NC}"
    echo ""
    
    count=1
    while true; do
        echo -n "API Key $count: "
        read -r key_input
        
        # 빈 입력시 종료
        if [ -z "$key_input" ]; then
            break
        fi
        
        # 환경변수 설정
        key_var="OPENAI_API_KEY_$count"
        export $key_var="$key_input"
        echo -e "✅ $key_var: 설정됨"
        
        count=$((count + 1))
        
        # 최대 10개까지만
        if [ $count -gt 10 ]; then
            echo -e "${YELLOW}⚠️ 최대 10개까지만 설정 가능합니다.${NC}"
            break
        fi
    done
fi

# 설정된 키 확인
echo -e "${BLUE}📊 설정된 API 키 현황:${NC}"
echo "========================"

key_count=0
for i in {1..20}; do
    key_var="OPENAI_API_KEY_$i"
    key_value="${!key_var}"
    if [ ! -z "$key_value" ]; then
        key_count=$((key_count + 1))
        echo -e "✅ $key_var: ${key_value:0:10}...${key_value: -8}"
    fi
done

if [ $key_count -eq 0 ]; then
    echo -e "${RED}❌ 설정된 API 키가 없습니다!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎯 총 $key_count 개의 API 키가 설정되었습니다!${NC}"
echo -e "${GREEN}📊 예상 Rate Limit: $((200000 * key_count)) TPM${NC}"
echo ""

# 환경변수 내보내기 스크립트 생성
cat > .env_multi_keys << EOF
# 다중 OpenAI API 키 설정 ($(date))
# 사용법: source .env_multi_keys
EOF

for i in {1..20}; do
    key_var="OPENAI_API_KEY_$i"
    key_value="${!key_var}"
    if [ ! -z "$key_value" ]; then
        echo "export $key_var=\"$key_value\"" >> .env_multi_keys
    fi
done

echo -e "${BLUE}💾 환경변수가 .env_multi_keys 파일에 저장되었습니다.${NC}"
echo -e "${YELLOW}📝 다음 번에는 'source .env_multi_keys'로 로드할 수 있습니다.${NC}"
echo ""

# 테스트 실행 안내
echo -e "${GREEN}🚀 이제 실험을 실행할 수 있습니다:${NC}"
echo "   ./run_full_experiment.sh 10    # 10개 질문으로 테스트"
echo "   ./run_full_experiment.sh       # 전체 실험"
echo ""

# 키 상태 확인
echo -e "${BLUE}🔍 API 키 상태 확인 중...${NC}"
python3 -c "
from config import OPENAI_API_KEYS
print(f'✅ config.py에서 {len(OPENAI_API_KEYS)}개 키 감지됨')
for i, key in enumerate(OPENAI_API_KEYS, 1):
    print(f'   Key {i}: ...{key[-8:]}')
" 2>/dev/null || echo -e "${YELLOW}⚠️ config.py 로딩 실패 (정상적일 수 있음)${NC}"
