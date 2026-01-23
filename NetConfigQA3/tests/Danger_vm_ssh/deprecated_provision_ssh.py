
import telnetlib3
import asyncio
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("provision_robust")

NODES = [
    {"name": "vIOS1", "port": 30113, "ip": "10.10.10.11"},
    {"name": "vIOS2", "port": 30114, "ip": "10.10.10.12"},
    {"name": "vIOS3", "port": 30115, "ip": "10.10.10.13"},
    {"name": "vIOS4", "port": 30116, "ip": "10.10.10.14"},
    {"name": "vIOS5", "port": 30117, "ip": "10.10.10.15"},
    {"name": "vIOS6", "port": 30118, "ip": "10.10.10.16"},
    {"name": "vIOS7", "port": 30119, "ip": "10.10.10.17"},
    {"name": "vIOS8", "port": 30120, "ip": "10.10.10.18"},
    {"name": "vIOS9", "port": 30121, "ip": "10.10.10.19"},
    {"name": "vIOS10", "port": 30122, "ip": "10.10.10.20"},
]

async def configure_node(node):
    host = "100.66.240.82"
    port = node["port"]
    name = node["name"]
    target_ip = node["ip"]
    
    logger.info(f"[{name}] Connecting to {host}:{port}...")
    try:
        reader, writer = await asyncio.wait_for(telnetlib3.open_connection(host, port), timeout=10)
    except Exception as e:
        logger.error(f"[{name}] Connection failed: {e}")
        return

    async def read_until_prompt(timeout=5):
        buffer = ""
        start = time.time()
        while time.time() - start < timeout:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1)
                if not data:
                    break
                buffer += data
                # Check for prompts
                if any(p in buffer for p in [">", "#", "[yes/no]:", "[yes]:", "selection [2]:", "Press RETURN"]):
                    return buffer
            except asyncio.TimeoutError:
                continue
        return buffer

    # Escape Setup Dialog Loop
    writer.write("\r\n")
    max_attempts = 20
    in_shell = False
    
    for _ in range(max_attempts):
        out = await read_until_prompt(timeout=3)
        logger.debug(f"[{name}] Read: {out[-50:] if out else 'Empty'}")
        
        if out.strip().endswith(">") or out.strip().endswith("#"):
            logger.info(f"[{name}] In shell!")
            in_shell = True
            break
        
        if "configuration command script was created" in out: 
             # Wait for the "selection [2]" prompt specifically if script was created
             pass

        if "Enter your selection" in out and "[2]" in out:
            logger.info(f"[{name}] Sending 0 to exit setup")
            writer.write("0\r\n")
        elif "[yes/no]" in out:
            logger.info(f"[{name}] Saying NO to setup")
            writer.write("no\r\n")
        elif "[yes]" in out:
            logger.info(f"[{name}] Saying NO to default yes")
            writer.write("no\r\n")
        elif "Press RETURN" in out:
            writer.write("\r\n")
        else:
            writer.write("\r\n")
        
        await asyncio.sleep(1)

    if not in_shell:
        logger.error(f"[{name}] Failed to reach shell.")
        writer.close()
        return

    # Helper to send command and wait for prompt (roughly)
    async def send_cmd(cmd, wait=1):
        logger.info(f"[{name}] CMD: {cmd}")
        writer.write(cmd + "\r\n")
        await asyncio.sleep(wait)
        # Consume output
        try:
            await reader.read(4000) 
        except:
            pass

    # Configure
    await send_cmd("enable")
    await send_cmd("conf t")
    await send_cmd("no logging console") # Stop annoying logs
    await send_cmd(f"hostname {name}")
    await send_cmd("interface Gi0/0")
    await send_cmd(f"ip address {target_ip} 255.255.255.0")
    await send_cmd("no shutdown")
    await send_cmd("exit")
    
    # SSH Setup
    await send_cmd("ip domain-name lab.local")
    await send_cmd("crypto key generate rsa modulus 1024", wait=3) 
    # Handle "How many bits in the modulus [512]:" or replacement prompt
    # Usually modulus 1024 argument handles it, but if it asks "overwrite?", say yes
    await send_cmd("yes", wait=1) # Just in case

    await send_cmd("username admin privilege 15 secret admin")
    await send_cmd("line vty 0 4")
    await send_cmd("transport input ssh")
    await send_cmd("login local")
    await send_cmd("end")
    await send_cmd("write memory", wait=3)
    
    logger.info(f"[{name}] Config done.")
    writer.close()

async def main():
    tasks = [configure_node(node) for node in NODES]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
