import os
import time
import asyncio
import discord
import aioboto3
import base64
import logging
import signal
import functools
import aiohttp
import threading
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
from discord.ext import commands, tasks
from mcrcon import MCRcon
from datetime import datetime
from contextlib import contextmanager, asynccontextmanager
from types import SimpleNamespace
import yaml
import shutil

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('minecraft_bot')

# --- CONFIGURATION ---

# Load config from YAML file
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Determine environment (prod or dev)
BOT_ENV = os.environ.get("BOT_ENV", "prod").lower()

# Discord
if BOT_ENV == "dev":
    DISCORD_TOKEN = config["discord"].get("token_DEV", config["discord"]["token"])
    CHANNEL_ID = int(config["discord"].get("channel_id_DEV", config["discord"]["channel_id"]))
else:
    DISCORD_TOKEN = config["discord"]["token"]
    CHANNEL_ID = int(config["discord"]["channel_id"])

# AWS Resources
AMI_ID = config["aws"]["ami_id"]
SECURITY_GROUP_ID = config["aws"]["security_group_id"]
EBS_VOLUME_ID = config["aws"]["ebs_volume_id"]
INSTANCE_TYPES = config["aws"]["instance_types"]
SUBNET_ID = config["aws"]["subnet_id"]
AWS_REGION = config["aws"]["region"]
KEY_PAIR_NAME = config["aws"]["key_pair_name"]
KEY_FILE_PATH = os.path.expanduser(f"~/.ssh/{KEY_PAIR_NAME}.pem")

# Minecraft
MINECRAFT_PORT = config["minecraft"]["port"]
RCON_PORT = config["minecraft"]["rcon_port"]
RCON_PASSWORD = config["minecraft"]["rcon_password"]

# --- STATE ---
last_player_seen = None
executor = ThreadPoolExecutor(max_workers=4)
minecraft_server_ready = False
is_starting_or_stopping = False

# --- RCON UTILS ---

@contextmanager
def ignore_signals():
    """Context manager to ignore signals in threads"""
    original_handlers = {}
    try:
        # Save and ignore SIGINT and SIGTERM
        for sig in (signal.SIGINT, signal.SIGTERM):
            original_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, signal.SIG_IGN)
        yield
    finally:
        # Restore original handlers
        for sig, handler in original_handlers.items():
            signal.signal(sig, handler)

def execute_rcon(ip, command):
    """Execute RCON command in a thread-safe manner"""
    with ignore_signals():
        try:
            with MCRcon(ip, RCON_PASSWORD, port=RCON_PORT, timeout=5) as mcr:
                return mcr.command(command)
        except Exception as e:
            logger.error(f"RCON execution error: {e}")
            return None

async def rcon_command(instance, command):
    public_dns = await get_instance_property(instance, 'public_dns_name')
    if not public_dns:
        logger.error("No public DNS name found for RCON connection.")
        return None
    logger.info(f"Executing RCON command on {public_dns}: {command}")
    try:
        from mcrcon import MCRcon
        with MCRcon(public_dns, RCON_PASSWORD, port=RCON_PORT, timeout=5) as mcr:
            resp = mcr.command(command)
            logger.info(f"RCON response: {resp}")
            return resp
    except Exception as e:
        logger.error(f"RCON execution error: {e}")
        return None

async def get_online_players(instance):
    """Get list of online players using RCON."""
    logger.debug("Checking online players")
    try:
        resp = await rcon_command(instance, "list")
        if resp is None:
            logger.warning("Failed to get player list (RCON not responsive)")
            return None
        if ":" in resp:
            players = resp.split(":")[1].strip()
            if players:
                player_list = [p.strip() for p in players.split(",")]
                logger.info(f"Online players: {player_list}")
                return player_list
        logger.info("No players online")
        return []
    except Exception as e:
        logger.warning(f"Exception in get_online_players: {e}")
        return None

async def warn_minecraft_players(instance):
    logger.info("Sending warning to Minecraft players about spot interruption")
    msg = "§c[Server] Spot instance interruption! Server will shut down in 30 seconds. Get to a safe place and log out!"
    await rcon_command(instance, f'say {msg}')

async def wait_for_volume_attachment(client, volume_id, max_attempts=30):
    """Wait for volume to attach with async sleep"""
    for attempt in range(max_attempts):
        try:
            volumes = await client.describe_volumes(VolumeIds=[volume_id])
            volume = volumes['Volumes'][0]
            if volume['State'] == 'in-use':
                logger.info("Storage volume attached successfully")
                return True
            await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"Error checking volume state: {e}")
            return False
    return False

async def wait_for_instance_state(instance, target_state='running', max_attempts=60):
    """Wait for instance to reach desired state with async sleep"""
    if instance is None:
        return False
        
    for attempt in range(max_attempts):
        try:
            await instance.reload()
            state = await get_instance_state(instance)
            if state == target_state:
                return True
            await asyncio.sleep(2)
        except Exception as e:
            logger.error(f"Error checking instance state: {e}")
            return False
    return False

# --- EC2 MANAGEMENT ---

async def get_instance_state(instance):
    """Helper function to safely get instance state"""
    if instance is None:
        return 'unknown'
    try:
        state = await instance.state
        return state['Name']
    except Exception as e:
        logger.error(f"Error getting instance state: {e}")
        return 'unknown'

async def get_instance_property(instance, property_name):
    """Helper function to safely get instance properties"""
    if instance is None:
        return None
    try:
        prop = getattr(instance, property_name)
        # Handle both async properties and regular properties
        if hasattr(prop, '__await__'):
            return await prop
        return prop
    except Exception as e:
        logger.error(f"Error getting instance property {property_name}: {e}")
        return None

# --- GLOBAL INSTANCES ---

# --- DISCORD BOT SETUP ---
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# --- AWS SESSION MANAGEMENT ---
class AWSManager:
    def __init__(self):
        self.session = aioboto3.Session(region_name=AWS_REGION)
        self._clients = {}
        self._resources = {}
        
    async def get_client(self, service_name):
        """Get an AWS client"""
        if service_name not in self._clients:
            self._clients[service_name] = await self.session.client(service_name).__aenter__()
        return self._clients[service_name]
        
    async def get_resource(self, service_name):
        """Get an AWS resource"""
        if service_name not in self._resources:
            self._resources[service_name] = await self.session.resource(service_name).__aenter__()
        return self._resources[service_name]

    async def cleanup(self):
        """Cleanup AWS sessions"""
        # Cleanup clients
        for client in self._clients.values():
            try:
                await client.__aexit__(None, None, None)
            except Exception as e:
                logger.error(f"Error cleaning up AWS client: {e}")
        self._clients.clear()
        
        # Cleanup resources
        for resource in self._resources.values():
            try:
                await resource.__aexit__(None, None, None)
            except Exception as e:
                logger.error(f"Error cleaning up AWS resource: {e}")
        self._resources.clear()

# Create global AWS manager
aws = AWSManager()

async def get_minecraft_instance():
    """Find the Minecraft server instance if it exists"""
    logger.debug("Searching for Minecraft server instance")
    try:
        ec2 = await aws.get_resource('ec2')
        try:
            filters = [
                {'Name': 'tag:Purpose', 'Values': ['MinecraftSpot']},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
            ]
            
            # Get the collection of instances
            instances = ec2.instances.filter(Filters=filters)
            
            # Iterate through the collection (it's already an async iterator)
            async for instance in instances:
                # We only need the first matching instance
                state = await get_instance_property(instance, 'state')
                logger.debug(f"Found instance: {instance.id} (state: {state['Name']})")
                return instance
                
            logger.debug("No matching instances found")
            return None
            
        finally:
            await ec2.__aexit__(None, None, None)
            
    except Exception as e:
        logger.error(f"Error while searching for Minecraft instance: {e}")
        return None

async def get_instance_status():
    global minecraft_server_ready
    instance = await get_minecraft_instance()
    if not instance:
        logger.info("No instance found, status: stopped")
        return "stopped"
    try:
        await instance.reload()
        state = await get_instance_state(instance)
        logger.info(f"Instance state: {state}")
        if state == 'running':
            try:
                ip_address = await get_instance_property(instance, 'public_ip_address')
                players = None
                if ip_address and minecraft_server_ready:
                    players = await get_online_players(instance)
                if players is not None and minecraft_server_ready:
                    logger.info("Minecraft server is running and responsive")
                    return "running"
                logger.info("Instance is running but Minecraft server is still starting or not responding to RCON")
                return "starting"
            except Exception as e:
                logger.warning(f"Failed to check Minecraft server status: {e}")
                return "starting"
        elif state == 'pending':
            return "starting"
        elif state in ['stopping', 'stopped']:
            return "stopped"
        else:
            return "unknown"
    except Exception as e:
        logger.error(f"Error getting instance status: {e}")
        return "unknown"

async def ensure_key_pair():
    """Ensure SSH key pair exists in AWS and locally. Create in AWS if missing. Abort if AWS key exists but local private key is missing."""
    try:
        client = await aws.get_client('ec2')
        try:
            # Try to describe the key pair in AWS
            await client.describe_key_pairs(KeyNames=[KEY_PAIR_NAME])
            logger.info(f"SSH key pair {KEY_PAIR_NAME} already exists in AWS")
            # Check if the private key file exists locally
            if not os.path.exists(KEY_FILE_PATH):
                logger.error(f"Key pair '{KEY_PAIR_NAME}' exists in AWS but private key file is missing locally at {KEY_FILE_PATH}. Cannot recover private key. Please delete the key pair in AWS or specify a new key_pair_name in config.yaml.")
                return False
            return True
        except Exception:
            # Key doesn't exist in AWS, so create it
            logger.info(f"Creating new SSH key pair in AWS: {KEY_PAIR_NAME}")
            response = await client.create_key_pair(KeyName=KEY_PAIR_NAME)
            private_key = response['KeyMaterial']
            os.makedirs(os.path.dirname(KEY_FILE_PATH), exist_ok=True)
            with open(KEY_FILE_PATH, 'w') as f:
                f.write(private_key)
            os.chmod(KEY_FILE_PATH, 0o600)
            logger.info(f"SSH key pair created in AWS and saved to {KEY_FILE_PATH}")
            return True
        finally:
            await client.__aexit__(None, None, None)
    except Exception as e:
        logger.error(f"Error managing SSH key pair: {e}")
        return False

async def get_ssh_connection_info():
    """Get SSH connection information for the current instance"""
    instance = await get_minecraft_instance()
    if not instance:
        return None
    try:
        state = await get_instance_state(instance)
        if state != 'running':
            return None
        username = "ec2-user"  # Default user for Amazon Linux 2023
        ip_address = await get_instance_property(instance, 'public_ip_address')
        if not os.path.exists(KEY_FILE_PATH):
            # If the key file is missing locally, try to create it (will only succeed if AWS keypair doesn't exist yet)
            await ensure_key_pair()
        if not ip_address:
            return None
        return {
            'username': username,
            'ip': ip_address,
            'key_file': KEY_FILE_PATH,
            'command': f"ssh -i {KEY_FILE_PATH} {username}@{ip_address}"
        }
    except Exception as e:
        logger.error(f"Error getting SSH connection info: {e}")
        return None

async def start_spot_instance():
    global minecraft_server_ready, is_starting_or_stopping
    minecraft_server_ready = False
    is_starting_or_stopping = True
    logger.info("=== Starting Minecraft Server ===")
    channel = bot.get_channel(CHANNEL_ID)

    # Ensure the key pair exists in AWS before launching the instance
    if not await ensure_key_pair():
        await channel.send(f"❌ Could not create or verify the EC2 key pair '{KEY_PAIR_NAME}'. Aborting.")
        is_starting_or_stopping = False
        return

    # Check if instance already exists
    existing_instance = await get_minecraft_instance()
    if existing_instance:
        status = await get_instance_status()
        logger.warning(f"Instance already exists with status: {status}")
        await channel.send(f"❌ Server instance already exists (status: {status})")
        return

    spot_request_id = None  # Ensure this is always defined for the finally block
    try:
        # Get EC2 client
        ec2 = await aws.get_client('ec2')
        try:
            # Check EBS volume availability
            volumes = await ec2.describe_volumes(VolumeIds=[EBS_VOLUME_ID])
            if volumes['Volumes'][0]['State'] != 'available':
                await channel.send(f"❌ EBS volume is not available (current state: {volumes['Volumes'][0]['State']})")
                await channel.send("ℹ️ The EBS volume is likely still being dismounted. Please wait a minute and try again.")
                return

            # Request spot instance
            await channel.send("🔄 Requesting spot instance...")
            response = await ec2.request_spot_instances(
                InstanceCount=1,
                LaunchSpecification={
                    "ImageId": AMI_ID,
                    "InstanceType": INSTANCE_TYPES[0],
                    "SecurityGroupIds": [SECURITY_GROUP_ID],
                    "SubnetId": SUBNET_ID,
                    "KeyName": KEY_PAIR_NAME
                },
                Type="one-time"
            )
            spot_request_id = response["SpotInstanceRequests"][0]["SpotInstanceRequestId"]

            # Wait for spot instance fulfillment
            await channel.send("⏳ Waiting for spot instance to be fulfilled...")
            instance_id = await wait_for_spot_fulfillment(ec2, spot_request_id)
            if not instance_id:
                await channel.send("❌ Spot instance request failed or timed out")
                return

            # Fetch the instance type of the fulfilled spot instance
            instance_desc = await ec2.describe_instances(InstanceIds=[instance_id])
            instance_type = instance_desc['Reservations'][0]['Instances'][0]['InstanceType']
            await channel.send(f"🖥️ Spot instance fulfilled! Selected instance type: `{instance_type}`")

            # Tag the instance
            await ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'Purpose', 'Value': 'MinecraftSpot'},
                    {'Key': 'Name', 'Value': 'Minecraft Server'}
                ]
            )

            # Attach EBS volume
            await channel.send("💾 Attaching storage volume...")
            await ec2.attach_volume(
                VolumeId=EBS_VOLUME_ID,
                InstanceId=instance_id,
                Device="/dev/xvdf"
            )
            if not await wait_for_volume_attachment(ec2, EBS_VOLUME_ID):
                raise Exception("Volume attachment timed out")

            # Wait for instance to be ready
            await channel.send("🚀 Waiting for instance to start...")
            instance = await get_minecraft_instance()
            if not await wait_for_instance_state(instance, 'running'):
                raise Exception("Instance failed to reach running state")

            # Wait for and get the public IP
            await channel.send("🌐 Waiting for public IP assignment...")
            ip_address = None
            for _ in range(30):  # Try for up to 2.5 minutes
                await instance.reload()
                ip_address = await get_instance_property(instance, 'public_ip_address')
                if ip_address:
                    break
                await asyncio.sleep(5)

            if not ip_address:
                raise Exception("Failed to get instance public IP address")

            await channel.send(f"✨ Instance is running with IP: `{ip_address}`")

            # Get the public DNS name for SSH
            public_dns = await get_instance_property(instance, 'public_dns_name')
            ssh_target = public_dns if public_dns else ip_address

            # Wait a bit for SSH to be available
            await channel.send("⏳ Waiting 30 seconds before attempting SSH access...")
            await asyncio.sleep(30)
            ssh_ready = False
            for attempt in range(1, 13):  # 2 minute timeout
                logger.info(f"[SSH Check] Attempt {attempt}: Checking SSH access on {ssh_target}")
                ssh_cmd = f"ssh -i {KEY_FILE_PATH} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ec2-user@{ssh_target} 'echo SSH_OK'"
                result = await run_command(ssh_cmd)
                logger.info(f"[SSH Check] Attempt {attempt} result: returncode={result.returncode}, stdout={result.stdout.strip()}, stderr={result.stderr.strip()}")
                if result.returncode == 0 and 'SSH_OK' in result.stdout:
                    logger.info(f"[SSH Check] SSH is ready at {ssh_target}")
                    ssh_ready = True
                    break
                await asyncio.sleep(5)
            if not ssh_ready:
                await channel.send("❌ SSH connection could not be established after multiple attempts. Please check the instance and security group settings.")
                logger.error(f"[SSH Check] SSH connection could not be established after multiple attempts at {ssh_target}")
                raise Exception("SSH connection failed")

            # Mount volume and start server
            await channel.send("🔧 Starting Minecraft server setup (step-by-step)...")
            ssh_cmd_base = f"ssh -i {KEY_FILE_PATH} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ec2-user@{ssh_target}"
            commands = [
                ("Install Java, screen, and netcat", "sudo dnf install -y java-21-amazon-corretto-devel screen nc"),
                ("Create mount directory", "sudo mkdir -p /mnt/minecraft"),
                ("Mount EBS volume", "sudo mount /dev/xvdf /mnt/minecraft"),
                ("Touch marker file", "sudo touch /mnt/minecraft/iwashere.piss"),
                ("Make start script executable", "sudo chmod +x /mnt/minecraft/startMinecraft.sh"),
                ("Start Minecraft in screen", "cd /mnt/minecraft && screen -dmS minecraft sudo ./startMinecraft.sh")
            ]
            for desc, cmd in commands:
                await channel.send(f"➡️ {desc}...")
                logger.info(f"Running on instance: {cmd}")
                result = await run_command(f"{ssh_cmd_base} '{cmd}'")
                if result.returncode == 0:
                    logger.info(f"SUCCESS: {desc}")
                    await channel.send(f"✅ {desc} succeeded.")
                    # Only set minecraft_server_ready = True after the screen command
                    if desc == "Start Minecraft in screen":
                        minecraft_server_ready = True
                else:
                    logger.error(f"FAILED: {desc} (code {result.returncode})\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
                    await channel.send(f"❌ {desc} failed!\nSTDOUT: ```{result.stdout.strip()}```\nSTDERR: ```{result.stderr.strip()}```")
                    raise Exception(f"Command failed: {cmd}\nError: {result.stderr}")

            # Wait for server to start accepting RCON connections
            await channel.send("⏳ Waiting for Minecraft server to start (via RCON)...")
            server_ready = False
            for attempt in range(12):  # 2 minute timeout, 10s interval
                logger.info(f"[Readiness Check] Attempt {attempt+1}: Checking RCON on {ssh_target}")
                rcon_resp = await rcon_command(instance, "list")
                if rcon_resp is not None:
                    # Get both IP and hostname
                    ip_address = await get_instance_property(instance, 'public_ip_address')
                    public_dns = await get_instance_property(instance, 'public_dns_name')
                    await channel.send(f"✅ Server is ready!\nHostname: `{public_dns}`\nIP: `{ip_address}`\nConnect at: `{public_dns}:25565` or `{ip_address}:25565`")
                    logger.info(f"[Readiness Check] Server is ready at {public_dns}:25565 (RCON responsive)")
                    server_ready = True
                    # Set last_player_seen to now when server is ready
                    global last_player_seen
                    last_player_seen = time.time()
                    break
                await asyncio.sleep(10)
            if not server_ready:
                await channel.send("❌ Server did not start accepting RCON connections in time. Please check the logs or try again.")
                logger.warning(f"[Readiness Check] Server did not start accepting RCON connections in time at {ssh_target}:25565")

        finally:
            # Always cleanup spot request
            if spot_request_id:
                await ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[spot_request_id])
            await ec2.__aexit__(None, None, None)

    except Exception as e:
        logger.error(f"Error starting spot instance: {e}")
        await channel.send(f"❌ Error starting spot instance: {str(e)}")
        await stop_spot_instance()
    finally:
        is_starting_or_stopping = False

async def wait_for_spot_fulfillment(ec2, spot_request_id, timeout=300):
    """Wait for spot instance request to be fulfilled"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        desc = await ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[spot_request_id])
        sir = desc["SpotInstanceRequests"][0]
        state = sir["State"]
        
        if state == "active":
            return sir["InstanceId"]
        elif state == "failed":
            logger.error(f"Spot request failed: {sir.get('Status', {}).get('Message', 'Unknown error')}")
            return None
            
        await asyncio.sleep(5)
    return None

async def wait_for_minecraft_server(instance, timeout=240):
    """Wait for Minecraft server to start and respond"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        await asyncio.sleep(10)
        status = await get_instance_status()
        if status == "running":
            return True
    return False

async def stop_spot_instance():
    global minecraft_server_ready, is_starting_or_stopping
    minecraft_server_ready = False
    is_starting_or_stopping = True
    logger.info("=== Stopping Minecraft Server ===")
    channel = bot.get_channel(CHANNEL_ID)
    
    instance = await get_minecraft_instance()
    if not instance:
        logger.warning("No server instance found to stop")
        await channel.send("❌ No server instance found")
        return
        
    try:
        # Get instance IP
        ip_address = await get_instance_property(instance, 'public_ip_address')
        
        # Gracefully stop Minecraft server if running
        if ip_address:
            await channel.send("💾 Saving world data...")
            await rcon_command(instance, "say [Server] Server is shutting down, saving world...")
            await asyncio.sleep(1)
            await rcon_command(instance, "save-all")
            await channel.send("🔄 Stopping Minecraft server...")
            await rcon_command(instance, "stop")
            await asyncio.sleep(10)  # Wait for server to save and stop
        
        # Terminate the instance
        await channel.send("🔄 Terminating EC2 instance...")
        await instance.terminate()
        await channel.send("✅ Instance terminated successfully")
        
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
        await channel.send(f"⚠️ Warning: Error during shutdown: {str(e)}")
        # Still try to terminate the instance even if Minecraft shutdown fails
        try:
            await instance.terminate()
        except Exception as term_error:
            logger.error(f"Failed to terminate instance: {term_error}")
    finally:
        is_starting_or_stopping = False

async def run_command(command):
    """Run a shell command and return the result"""
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return SimpleNamespace(
        returncode=process.returncode,
        stdout=stdout.decode() if stdout else '',
        stderr=stderr.decode() if stderr else ''
    )
    
async def get_spot_price(instance_type, region=AWS_REGION):
    """Fetch the latest spot price for the given instance type in the configured region."""
    try:
        client = await aws.get_client('ec2')
        prices = await client.describe_spot_price_history(
            InstanceTypes=[instance_type],
            ProductDescriptions=['Linux/UNIX'],
            MaxResults=1,
            StartTime=datetime.utcnow(),
            EndTime=datetime.utcnow(),
        )
        await client.__aexit__(None, None, None)
        if prices['SpotPriceHistory']:
            price = float(prices['SpotPriceHistory'][0]['SpotPrice'])
            return price
        else:
            return None
    except Exception as e:
        logger.error(f"Error fetching spot price for {instance_type}: {e}")
        return None

def is_ssh_available():
    """Check if the 'ssh' command is available in the system PATH."""
    return shutil.which('ssh') is not None

async def ensure_ssh_installed():
    """Ensure the 'ssh' command is available. Attempt to install if missing."""
    if is_ssh_available():
        return True
    logger.warning("'ssh' command not found. Attempting to install...")
    # Try to install with dnf (Amazon Linux, Fedora, RHEL)
    proc = await asyncio.create_subprocess_shell(
        'sudo dnf install -y openssh-clients',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0 and is_ssh_available():
        logger.info("Successfully installed openssh-clients with dnf.")
        return True
    # Try to install with apt-get (Debian/Ubuntu)
    proc = await asyncio.create_subprocess_shell(
        'sudo apt-get update && sudo apt-get install -y openssh-client',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0 and is_ssh_available():
        logger.info("Successfully installed openssh-client with apt-get.")
        return True
    logger.error("Failed to install 'ssh' command. Please install it manually.")
    return False

# Call ensure_ssh_installed at startup
async def bot_startup_checks():
    if not await ensure_ssh_installed():
        logger.error("'ssh' command is required but could not be installed. Exiting.")
        raise SystemExit(1)

# --- DISCORD COMMANDS ---
@bot.command()
async def start(ctx):
    status = await get_instance_status()
    if status != "stopped":
        await ctx.send(f"Server is already {status}.")
        return
    await ctx.send("Starting Minecraft server...")
    await start_spot_instance()

@bot.command()
async def stop(ctx):
    status = await get_instance_status()
    if status == "stopped":
        await ctx.send("Server is not running.")
        return
    await ctx.send("Stopping Minecraft server...")
    await stop_spot_instance()

@bot.command()
async def status(ctx):
    instance = await get_minecraft_instance()
    if not instance:
        await ctx.send("Status: No server instance found")
        return
        
    status = await get_instance_status()
    await instance.reload()  # Get fresh instance data
    
    # Get actual instance type
    actual_instance_type = await get_instance_property(instance, 'instance_type')
    spot_price = await get_spot_price(actual_instance_type)
    if spot_price is not None:
        cost_hour = spot_price
        cost_day = spot_price * 24
        cost_month = spot_price * 24 * 30
        price_msg = (f"💸 Instance type: `{actual_instance_type}`\n"
                     f"Spot price: `${spot_price:.4f}`/hr\n"
                     f"= `${cost_day:.2f}`/day, `${cost_month:.2f}`/month")
    else:
        price_msg = f"💸 Instance type: `{actual_instance_type}`\nSpot price: unavailable"
    
    # Await launch_time property
    launch_time = await get_instance_property(instance, 'launch_time')
    ip_address = await get_instance_property(instance, 'public_ip_address')
    public_dns = await get_instance_property(instance, 'public_dns_name')
    
    # Create a detailed status message
    status_lines = [
        f"Status: {status}",
        price_msg,
        f"Hostname: {public_dns}",
        f"IP: {ip_address}",
        f"Connect at: {public_dns}:25565 or {ip_address}:25565",
        f"Launch Time: {launch_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    ]
    
    if status == "running":
        try:
            players = await get_online_players(instance)
            player_count = len(players) if players is not None else 0
            status_lines.append(f"Players Online: {player_count}")
            if players:
                status_lines.append(f"Online Players: {', '.join(players)}")
        except Exception:
            status_lines.append("Player count unavailable")
    
    await ctx.send("\n".join(status_lines))

@bot.command()
async def message(ctx, *, text: str):
    """Send a message to the Minecraft server. Usage: !message <text>"""
    instance = await get_minecraft_instance()
    if not instance or await get_instance_status() != "running":
        await ctx.send("❌ Cannot send message: Server is not running")
        return
        
    try:
        response = await rcon_command(instance, f"say {text}")
        if response is not None:
            await ctx.send(f"✅ Message sent to Minecraft server: `{text}`")
        else:
            await ctx.send("❌ Failed to send message: No response from server")
    except Exception as e:
        await ctx.send(f"❌ Failed to send message: {str(e)}")

@bot.command()
async def whitelist(ctx, username: str):
    """Add a player to the server whitelist. Usage: !whitelist <username>"""
    instance = await get_minecraft_instance()
    if not instance or await get_instance_status() != "running":
        await ctx.send("❌ Cannot modify whitelist: Server is not running")
        return
    
    try:
        # Add player to whitelist
        response = await rcon_command(instance, f"whitelist add {username}")
        if response and "Added" in response:
            await ctx.send(f"✅ Added `{username}` to the whitelist")
        elif response and "already whitelisted" in response:
            await ctx.send(f"ℹ️ `{username}` is already on the whitelist")
        else:
            await ctx.send(f"❌ Failed to add `{username}` to whitelist: {response}")
    except Exception as e:
        await ctx.send(f"❌ Error modifying whitelist: {str(e)}")

@bot.command()
async def ssh(ctx):
    """Get SSH connection information for the Minecraft server"""
    status = await get_instance_status()
    if status != "running":
        await ctx.send(f"❌ Cannot get SSH info: Server is not running (status: {status})")
        return
        
    connection_info = await get_ssh_connection_info()
    if not connection_info:
        await ctx.send("❌ Failed to get SSH connection information")
        return
        
    # Create an embed with connection details
    embed = discord.Embed(
        title="🔐 SSH Connection Details",
        description="Use these details to connect to the Minecraft server for troubleshooting.",
        color=0x00ff00
    )
    
    embed.add_field(
        name="Connection Command",
        value=f"```bash\n{connection_info['command']}\n```",
        inline=False
    )
    
    embed.add_field(
        name="Connection Details",
        value=(
            f"**Username:** `{connection_info['username']}`\n"
            f"**IP Address:** `{connection_info['ip']}`\n"
            f"**Key File:** `{connection_info['key_file']}`"
        ),
        inline=False
    )
    
    embed.add_field(
        name="Important Notes",
        value=(
            "• The key file is required for SSH access\n"
            "• Set file permissions: `chmod 600 minecraft-spot-key.pem`\n"
            "• The server runs on Amazon Linux 2023\n"
            "• Use `sudo` for administrative commands"
        ),
        inline=False
    )
    
    await ctx.send(embed=embed)

@bot.command()
async def help(ctx):
    """Show help information about the bot and its commands"""
    help_embed = discord.Embed(
        title="🎮 Minecraft Server Manager",
        description=(
            "This bot manages a Minecraft server using AWS Spot Instances.\n\n"
            "**What are Spot Instances?**\n"
            "Spot instances are unused AWS servers available at a discount (up to 90% cheaper!). "
            "The server may need to shut down if AWS needs the capacity back, but we'll give you a 2-minute warning if that happens."
        ),
        color=0x00ff00
    )

    commands_info = {
        "!help": "Show this help message",
        "!start": "Start the Minecraft server (takes ~5 minutes to fully start)",
        "!stop": "Safely stop the Minecraft server and save all worlds",
        "!status": "Check if the server is running, starting, or stopped",
        "!message <text>": "Send a message to all players on the Minecraft server",
        "!whitelist <username>": "Add a player to the server whitelist",
        "!ssh": "Get SSH connection details for troubleshooting the server",
        "!suicide": "Force the bot to terminate itself (systemd should restart it). Useful for remote restarts."
    }

    commands_text = "\n\n".join(f"**{cmd}**\n{desc}" for cmd, desc in commands_info.items())
    help_embed.add_field(name="📝 Commands", value=commands_text, inline=False)

    help_embed.add_field(
        name="⚡ Quick Tips",
        value=(
            "• The server will automatically shut down after 5 minutes of inactivity\n"
            "• You'll get a warning message if AWS needs to reclaim the spot instance\n"
            "• World data is safely stored and persists between server restarts\n"
            "• Players must be whitelisted before they can join the server\n"
            "• Use !ssh to get connection details for troubleshooting"
        ),
        inline=False
    )

    await ctx.send(embed=help_embed)

@bot.command()
async def debug(ctx):
    """Get detailed debug information about the Minecraft server"""
    instance = await get_minecraft_instance()
    if not instance:
        await ctx.send("❌ No server instance found")
        return
        
    status = await get_instance_status()
    if status != "running":
        await ctx.send(f"❌ Server is not running (status: {status})")
        return
        
    try:
        ip_address = await get_instance_property(instance, 'public_ip_address')
        if not ip_address:
            await ctx.send("❌ Could not get instance IP address")
            return
            
        # Create an embed for the debug info
        embed = discord.Embed(
            title="🔍 Server Debug Information",
            description="Detailed information about the Minecraft server instance",
            color=0x00ff00
        )
        
        # Get instance metadata
        instance_id = await get_instance_property(instance, 'id')
        launch_time = await get_instance_property(instance, 'launch_time')
        instance_type = await get_instance_property(instance, 'instance_type')
        
        embed.add_field(
            name="🖥️ Instance Information",
            value=(
                f"**ID:** `{instance_id}`\n"
                f"**Type:** `{instance_type}`\n"
                f"**IP:** `{ip_address}`\n"
                f"**Launched:** {launch_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            ),
            inline=False
        )
        
        # Check SSH connectivity
        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {KEY_FILE_PATH} ec2-user@{ip_address} 'echo SSH_OK'"
        ssh_result = await run_command(ssh_cmd)
        ssh_status = "✅ Connected" if ssh_result.returncode == 0 else "❌ Not accessible"
        
        embed.add_field(
            name="🔐 SSH Status",
            value=ssh_status,
            inline=False
        )
        
        # Check mount status
        mount_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {KEY_FILE_PATH} ec2-user@{ip_address} 'mountpoint -q /mnt/minecraft && echo MOUNTED || echo NOT_MOUNTED'"
        mount_result = await run_command(mount_cmd)
        mount_status = "✅ Mounted" if mount_result.stdout.strip() == "MOUNTED" else "❌ Not mounted"
        
        embed.add_field(
            name="💾 Storage Status",
            value=mount_status,
            inline=False
        )
        
        # Try RCON connection
        minecraft_status = "Unknown"
        try:
            players = await get_online_players(instance)
            if players is not None:
                minecraft_status = f"✅ Running (Players: {len(players)})"
                if players:
                    minecraft_status += f"\nOnline: {', '.join(players)}"
            else:
                minecraft_status = "❌ Not responding to RCON"
        except Exception as e:
            minecraft_status = f"❌ Error: {str(e)}"
            
        embed.add_field(
            name="🎮 Minecraft Status",
            value=minecraft_status,
            inline=False
        )
        
        await ctx.send(embed=embed)
        
    except Exception as e:
        logger.error(f"Error in debug command: {e}")
        await ctx.send(f"❌ Error getting debug information: {str(e)}")

@bot.command()
async def suicide(ctx):
    """Terminate the bot process (systemd should restart it)."""
    await ctx.send("☠️ Suicide command received. Terminating bot process. If systemd is configured, the bot should restart shortly.")
    logger.warning("Suicide command received from Discord. Terminating bot process.")
    await asyncio.sleep(1)  # Give Discord message a moment to send
    os._exit(0)

# --- BACKGROUND TASKS ---

@tasks.loop(seconds=60)
async def check_player_activity():
    global last_player_seen, minecraft_server_ready, is_starting_or_stopping
    if is_starting_or_stopping:
        logger.debug("Skipping player activity check: start/stop in progress.")
        return
    logger.debug("Checking player activity")
    try:
        instance = await get_minecraft_instance()
        if not instance:
            return
        status = await get_instance_status()
        if status != "running" or not minecraft_server_ready:
            return
        ip_address = await get_instance_property(instance, 'public_ip_address')
        if not ip_address:
            return
        players = await get_online_players(instance)
        # Initialize last_player_seen if server is running and it's None
        if last_player_seen is None:
            last_player_seen = time.time()
        if players:
            last_player_seen = time.time()
            logger.info(f"Active players detected: {players}")
        elif last_player_seen and time.time() - last_player_seen > 300:
            logger.info("No players for 5 minutes, initiating shutdown")
            channel = bot.get_channel(CHANNEL_ID)
            await channel.send("No players for 5 minutes, shutting down server.")
            await stop_spot_instance()
            last_player_seen = None
    except Exception as e:
        logger.error(f"Error in player activity check: {e}")

@tasks.loop(seconds=30)
async def check_spot_interruption():
    global is_starting_or_stopping
    if is_starting_or_stopping:
        logger.debug("Skipping spot interruption check: start/stop in progress.")
        return
    logger.debug("Checking for spot interruption")
    try:
        instance = await get_minecraft_instance()
        if not instance:
            return
        status = await get_instance_status()
        if status != "running":
            return
        instance_id = await get_instance_property(instance, 'id')
        if not instance_id:
            return
        try:
            client = await aws.get_client('ec2')
            try:
                statuses = await client.describe_instance_status(InstanceIds=[instance_id])
                instance_statuses = statuses.get("InstanceStatuses", [])
                if instance_statuses and "Events" in instance_statuses[0]:
                    for event in instance_statuses[0]["Events"]:
                        if event["Code"] == "instance-stop":
                            logger.warning("Spot interruption detected!")
                            channel = bot.get_channel(CHANNEL_ID)
                            await channel.send(
                                "⚠️ **Spot Instance Interruption Detected!**\n"
                                "AWS needs this server. You have 2 minutes to save your work!\n"
                                "The server will shut down automatically."
                            )
                            ip_address = await get_instance_property(instance, 'public_ip_address')
                            if ip_address:
                                await warn_minecraft_players(instance)
                            await asyncio.sleep(30)
                            await stop_spot_instance()
                            break
            finally:
                await client.__aexit__(None, None, None)
        except Exception as e:
            logger.error(f"Error checking instance status: {e}")
    except Exception as e:
        logger.error(f"Error checking spot interruption: {e}")

@check_player_activity.before_loop
async def before_player_check():
    await bot.wait_until_ready()
    logger.info("Player activity checker initialized")

@check_spot_interruption.before_loop
async def before_spot_check():
    await bot.wait_until_ready()
    logger.info("Spot interruption checker initialized")

@check_player_activity.after_loop
async def after_player_check():
    logger.info("Player activity checker stopped")
    if check_player_activity.failed():
        logger.error(f"Player activity checker failed: {check_player_activity.get_task().exception()}")

@check_spot_interruption.after_loop
async def after_spot_check():
    logger.info("Spot interruption checker stopped")
    if check_spot_interruption.failed():
        logger.error(f"Spot interruption checker failed: {check_spot_interruption.get_task().exception()}")

# Update the bot event handlers
@bot.event
async def on_ready():
    global minecraft_server_ready
    logger.info(f"=== Bot Started ===")
    logger.info(f"Connected as: {bot.user}")
    logger.info(f"Discord Channel ID: {CHANNEL_ID}")
    logger.info(f"AWS Region: {AWS_REGION}")
    logger.info(f"Instance Types: {INSTANCE_TYPES}")

    # Check if server is already running and RCON is responsive
    instance = await get_minecraft_instance()
    if instance:
        state = await get_instance_state(instance)
        if state == 'running':
            try:
                players = await get_online_players(instance)
                if players is not None:
                    minecraft_server_ready = True
                    logger.info("Detected running Minecraft server with responsive RCON on startup. Setting minecraft_server_ready = True.")
            except Exception as e:
                logger.warning(f"Could not check RCON on startup: {e}")

    # Start background tasks
    if not check_player_activity.is_running():
        check_player_activity.start()
    if not check_spot_interruption.is_running():
        check_spot_interruption.start()
    logger.info("Bot is ready!")

    # Announce bot is alive in the Discord channel
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        await channel.send("I'm alive! Run `!help` to see what I can do!")

@bot.event
async def on_shutdown():
    """Handle bot shutdown"""
    logger.info("Bot is shutting down...")
    
    # Cancel background tasks
    try:
        if check_player_activity.is_running():
            check_player_activity.cancel()
        if check_spot_interruption.is_running():
            check_spot_interruption.cancel()
    except Exception as e:
        logger.error(f"Error cancelling background tasks: {e}")
    
    await cleanup()

# --- CLEANUP ---

async def cleanup():
    """Cleanup function to be called on shutdown"""
    logger.info("Cleaning up resources...")
    try:
        # Cleanup AWS sessions
        await aws.cleanup()
        
        logger.info("Cleanup completed successfully")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

# --- MAIN ---

if __name__ == "__main__":
    try:
        asyncio.run(bot_startup_checks())
        bot.run(DISCORD_TOKEN)
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Bot crashed: {e}")
    finally:
        # Ensure cleanup runs even if bot crashes
        asyncio.run(cleanup())