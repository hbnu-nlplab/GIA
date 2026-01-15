
import asyncio
import telnetlib3
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# vIOS2 정보 (로그에서 확인된 Port)
HOST = "100.66.240.82"
PORT = 30114  # vIOS2 Port
DEVICE_NAME = "vIOS2"

async def check_ip():
    logger.info(f"Connecting to {DEVICE_NAME} ({HOST}:{PORT})...")
    
    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(HOST, PORT), timeout=10
        )
        logger.info("Connected!")
        
        # 엔터 몇 번 쳐서 프롬프트 확인
        writer.write("\r\n\r\n")
        await asyncio.sleep(1)
        
        # Enable 모드 (비번 123)
        writer.write("enable\r\n")
        await asyncio.sleep(0.5)
        writer.write("123\r\n")
        await asyncio.sleep(0.5)
        
        # IP Interface 확인
        logger.info("Checking IP Interface...")
        writer.write("show ip interface brief\r\n")
        await asyncio.sleep(1)
        
        output = await reader.read(4096)
        print("\n--- SH IP INT BR ---")
        print(output)
        print("--------------------\n")
        
        # Running Config 확인 (Gi0/0)
        logger.info("Checking Running Config (Gi0/0)...")
        writer.write("show run interface gi0/0\r\n")
        await asyncio.sleep(1)
        
        output = await reader.read(4096)
        print("\n--- SH RUN INT GI0/0 ---")
        print(output)
        print("------------------------\n")
        
        # Ping Gateway
        logger.info("Pinging Gateway (10.10.10.1)...")
        writer.write("ping 10.10.10.1\r\n")
        await asyncio.sleep(2)
        
        output = await reader.read(4096)
        print("\n--- PING 10.10.10.1 ---")
        print(output)
        print("-----------------------\n")

        writer.close()
        
    except Exception as e:
        logger.error(f"Failed: {e}")

if __name__ == "__main__":
    asyncio.run(check_ip())
