#!/bin/bash

echo "Setting up Minecraft Discord Bot on Amazon Linux 2023..."

# Update system packages
echo "Updating system packages..."
sudo dnf update -y

# Install Python 3.9 and development tools
echo "Installing Python and development tools..."
sudo dnf groupinstall "Development Tools" -y
sudo dnf install python3 python3-pip python3-devel openssl-devel -y

# Create virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install required Python packages
echo "Installing Python packages..."
pip install discord.py aioboto3 paramiko aiohttp async-timeout PyYAML
pip install mcrcon==0.7

# Create requirements.txt for future reference
pip freeze > requirements.txt

# Create service file for running the bot
echo "Creating systemd service file..."
sudo tee /etc/systemd/system/minecraft-discord-bot.service << EOL
[Unit]
Description=Minecraft Discord Bot
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
Environment=DISCORD_BOT_TOKEN=YourTokenHere
Environment=DISCORD_CHANNEL_ID=YourChannelIDHere
ExecStart=$(pwd)/venv/bin/python bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

# Create script to run the bot
echo "Creating run script..."
tee run_bot.sh << EOL
#!/bin/bash
source venv/bin/activate

# Discord Configuration
export DISCORD_BOT_TOKEN="YourTokenHere"
export DISCORD_CHANNEL_ID="YourChannelIDHere"

python bot.py
EOL

# Make run script executable
chmod +x run_bot.sh

echo "
Setup complete! Here's what you need to do next:

1. Set your Discord bot token:
   Edit run_bot.sh and replace 'your_discord_token_here' with your actual Discord bot token

2. You can run the bot in two ways:

   a) Using the run script (for testing):
      ./run_bot.sh

   b) Using systemd (recommended for production):
      sudo systemctl enable minecraft-discord-bot
      sudo systemctl start minecraft-discord-bot

3. To view bot logs when running as a service:
      sudo journalctl -u minecraft-discord-bot -f

Note: The t3a.nano instance has limited memory, so the bot is set up in a virtual
      environment to minimize memory usage. The systemd service will automatically
      restart the bot if it crashes.
" 