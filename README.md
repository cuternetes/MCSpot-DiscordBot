# MCSpot - The Discord Bot!

MCSpot is a powerful Discord bot that lets you manage a Minecraft server running on AWS EC2 Spot Instances, directly from your Discord server. It's designed for cost-effective, on-demand Minecraft hosting, with features for starting/stopping the server, sending messages, managing whitelists, and more—all from Discord!

---

## TODO:

- Define AWS Infrastructure instructions

---

## Features

- **Start/Stop Minecraft Server:** Spin up or shut down your AWS EC2 Spot Instance with simple Discord commands.
- **Status Monitoring:** Check server and player status from Discord.
- **RCON Integration:** Send Minecraft server commands and messages.
- **Whitelist Management:** Add players to the server whitelist via Discord.
- **Spot Interruption Handling:** Warns players and safely shuts down if AWS reclaims the spot instance.
- **SSH Info:** Get SSH connection details for advanced management.
- **Automated Restarts:** Systemd service ensures the bot restarts if it crashes.

---

## Requirements

- **Amazon Linux 2023** (or similar Linux environment)
- **Python 3.9+**
- **AWS Account** with EC2, IAM, and EBS permissions
- **Discord Bot Token** and a Discord server/channel

---

## Setup

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd MCSpot-DiscordBot
```

### 2. Configure the Bot

Edit `config.yaml` with your credentials and settings:

```yaml
discord:
  token: "YOUR_DISCORD_BOT_TOKEN"
  channel_id: "YOUR_DISCORD_CHANNEL_ID"
aws:
  ami_id: "ami-xxxxxx"
  security_group_id: "sg-xxxxxx"
  ebs_volume_id: "vol-xxxxxx"
  instance_types:
    - m5.large
    - m5a.large
  subnet_id: "subnet-xxxxxx"
  region: "us-east-2"
  key_pair_name: "your-key-pair"
minecraft:
  port: 25565
  rcon_port: 25575
  rcon_password: "YourRconPasswordHere"
```

> **Note:** The SSH private key for the EC2 instance will be saved in your `~/.ssh` directory (e.g., `/home/youruser/.ssh/`).
> Make sure the user running the bot (including under systemd) has read access to this file and directory.

### 3. Run the Setup Script

```bash
chmod +x setup_bot.sh
./setup_bot.sh
```

This will:
- Install dependencies
- Set up a Python virtual environment
- Create a systemd service and a run script

### 4. Set Your Discord Bot Token

Edit `run_bot.sh` and replace the placeholders with your actual Discord bot token and channel ID:

```bash
export DISCORD_BOT_TOKEN="YourTokenHere"
export DISCORD_CHANNEL_ID="YourChannelIDHere"
```

---

## Usage

You can run the bot in two ways:

### For Testing

```bash
./run_bot.sh
```

### As a Systemd Service (Recommended)

```bash
sudo systemctl enable minecraft-discord-bot
sudo systemctl start minecraft-discord-bot
```

To view logs:

```bash
sudo journalctl -u minecraft-discord-bot -f
```

---

## Discord Commands

- `!start` — Start the Minecraft server (AWS Spot Instance)
- `!stop` — Stop the server
- `!status` — Show server and player status
- `!message <text>` — Send a message to all players
- `!whitelist <username>` — Add a player to the whitelist
- `!ssh` — Get SSH connection info
- `!help` — Show help message

---

## Notes

- The bot is optimized for low-memory instances (e.g., t3a.nano).
- The systemd service will auto-restart the bot if it crashes.
- Make sure your AWS credentials and permissions are set up properly.
- The SSH key for the EC2 instance is saved in `~/.ssh/` (e.g., `/home/youruser/.ssh/`).
- If running as a systemd service, ensure the service user has access to this directory and file.

---

## License

MIT License (or your preferred license) 