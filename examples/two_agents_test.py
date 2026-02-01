#!/usr/bin/env python3
"""
AgentMesh Two-Agent Communication Test

Run this script in TWO separate terminal windows to test real agent-to-agent communication.

Terminal 1 (Alice - listener):
    python3 examples/two_agents_test.py --name alice --listen

Terminal 2 (Bob - sender):
    python3 examples/two_agents_test.py --name bob --send-to <alice_amid>
"""

import sys
import os
import json
import asyncio
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone

# Add the openclaw-skill to path
sys.path.insert(0, str(Path(__file__).parent.parent / "openclaw-skill"))

from agentmesh.identity import Identity
from agentmesh.transport import RelayTransport
from agentmesh.discovery import RegistryClient

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("test")

# Production endpoints
REGISTRY_URL = "https://agentmesh.online/v1"
RELAY_URL = "wss://relay.agentmesh.online/v1/connect"

# Test data directory
TEST_DATA_DIR = Path(__file__).parent / ".test_agents"


class TestAgent:
    """A simple test agent for demonstrating AgentMesh communication."""

    def __init__(self, name: str):
        self.name = name
        self.data_dir = TEST_DATA_DIR / name
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load or generate identity
        self.identity = self._load_or_create_identity()

        # Initialize components
        self.registry = RegistryClient(REGISTRY_URL)
        self.transport = RelayTransport(
            identity=self.identity,
            relay_url=RELAY_URL,
            p2p_capable=True,
        )

        # Message queue for received messages
        self.received_messages = asyncio.Queue()

        # Setup message handler
        self.transport.on_message('receive', self._handle_message)

    def _load_or_create_identity(self) -> Identity:
        """Load existing identity or create a new one."""
        identity_path = self.data_dir / "identity.json"

        if identity_path.exists():
            logger.info(f"Loading existing identity for {self.name}")
            return Identity.load(identity_path)
        else:
            logger.info(f"Generating new identity for {self.name}")
            identity = Identity.generate()
            identity.save(identity_path)
            return identity

    @property
    def amid(self) -> str:
        return self.identity.amid

    async def register(self) -> bool:
        """Register this agent with the registry."""
        logger.info(f"Registering {self.name} ({self.amid[:12]}...) with registry")

        try:
            result = await self.registry.register(
                identity=self.identity,
                display_name=f"TestAgent-{self.name}",
                capabilities=["test/echo", "test/ping"],
            )
            logger.info(f"Registration successful: {result}")
            return True
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return False

    async def connect(self) -> bool:
        """Connect to the relay server."""
        logger.info(f"Connecting {self.name} to relay...")

        if await self.transport.connect():
            logger.info(f"Connected to relay")

            # Update status to online
            await self.registry.update_status(self.identity, "online")
            return True
        else:
            logger.error(f"Failed to connect to relay")
            return False

    async def disconnect(self):
        """Disconnect from the network."""
        await self.registry.update_status(self.identity, "offline")
        await self.transport.disconnect()
        logger.info(f"{self.name} disconnected")

    async def lookup(self, amid: str):
        """Look up another agent."""
        logger.info(f"Looking up agent: {amid[:12]}...")
        agent_info = await self.registry.lookup(amid)
        if agent_info:
            logger.info(f"Found agent: {agent_info.display_name or 'unnamed'}")
            return agent_info
        else:
            logger.warning(f"Agent not found: {amid}")
            return None

    async def send_message(self, to_amid: str, message: dict) -> bool:
        """Send a message to another agent."""
        logger.info(f"Sending message to {to_amid[:12]}...")

        # Create a simple message payload
        payload = json.dumps({
            'type': 'test_message',
            'from': self.amid,
            'from_name': self.name,
            'content': message,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

        await self.transport.send(
            to=to_amid,
            encrypted_payload=payload,
            message_type='message',
        )

        logger.info(f"Message sent")
        return True

    async def _handle_message(self, data: dict):
        """Handle incoming messages."""
        from_amid = data.get('from', 'unknown')
        payload = data.get('encrypted_payload', '{}')

        try:
            message = json.loads(payload)
            logger.info(f"")
            logger.info(f"{'='*50}")
            logger.info(f"MESSAGE RECEIVED from {from_amid[:12]}...")
            logger.info(f"   Type: {message.get('type')}")
            logger.info(f"   From: {message.get('from_name', 'unknown')}")
            logger.info(f"   Content: {message.get('content')}")
            logger.info(f"{'='*50}")
            logger.info(f"")

            await self.received_messages.put(message)

            # Auto-reply only for original test messages (not echo replies)
            # This prevents infinite ping-pong loops
            content = message.get('content', {})
            if message.get('type') == 'test_message' and isinstance(content, dict) and 'greeting' in content:
                reply = {
                    'type': 'echo_reply',
                    'original': content,
                    'reply': f"Hello from {self.name}! I received your message.",
                }
                await self.send_message(from_amid, reply)

        except json.JSONDecodeError:
            logger.warning(f"Received non-JSON message: {payload[:100]}")

    async def wait_for_message(self, timeout: float = 30.0):
        """Wait for an incoming message."""
        try:
            return await asyncio.wait_for(
                self.received_messages.get(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            return None


async def run_listener(name: str):
    """Run an agent in listener mode."""
    agent = TestAgent(name)

    print(f"\n{'='*60}")
    print(f"  AgentMesh Test Agent: {name}")
    print(f"  AMID: {agent.amid}")
    print(f"{'='*60}\n")

    # Register and connect
    if not await agent.register():
        return

    if not await agent.connect():
        return

    print(f"\n Agent {name} is online and listening!")
    print(f"\n Share this AMID with the other agent:")
    print(f"\n   {agent.amid}\n")
    print(f"Press Ctrl+C to stop\n")

    try:
        # Keep running and handle messages
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\nShutting down {name}...")
    finally:
        await agent.disconnect()


async def run_sender(name: str, target_amid: str):
    """Run an agent that sends messages to another agent."""
    agent = TestAgent(name)

    print(f"\n{'='*60}")
    print(f"  AgentMesh Test Agent: {name}")
    print(f"  AMID: {agent.amid}")
    print(f"  Target: {target_amid[:20]}...")
    print(f"{'='*60}\n")

    # Register and connect
    if not await agent.register():
        return

    if not await agent.connect():
        return

    # Look up the target agent
    target_info = await agent.lookup(target_amid)
    if not target_info:
        print(f"\n Could not find target agent. Make sure they are registered.")
        await agent.disconnect()
        return

    print(f"\n Found target agent: {target_info.display_name or target_amid[:12]}")
    print(f"  Status: {target_info.status}")
    print(f"  Capabilities: {target_info.capabilities}")

    # Send test messages
    print(f"\n Sending test messages...\n")

    messages = [
        {"greeting": "Hello from Bob!", "number": 1},
        {"greeting": "This is message #2", "number": 2},
        {"greeting": "Final test message", "number": 3},
    ]

    for i, msg in enumerate(messages, 1):
        print(f"Sending message {i}/{len(messages)}...")
        await agent.send_message(target_amid, msg)

        # Wait for reply
        print(f"Waiting for reply...")
        reply = await agent.wait_for_message(timeout=10.0)

        if reply:
            print(f"Got reply: {reply.get('reply', reply)}\n")
        else:
            print(f"No reply received (timeout)\n")

        await asyncio.sleep(1)

    print(f"\n Test complete!")
    await agent.disconnect()


async def run_interactive(name: str):
    """Run an agent in interactive mode."""
    agent = TestAgent(name)

    print(f"\n{'='*60}")
    print(f"  AgentMesh Interactive Test Agent: {name}")
    print(f"  AMID: {agent.amid}")
    print(f"{'='*60}\n")

    # Register and connect
    if not await agent.register():
        return

    if not await agent.connect():
        return

    print(f"\n Agent {name} is online!")
    print(f"\nCommands:")
    print(f"  send <amid> <message>  - Send a message")
    print(f"  lookup <amid>          - Look up an agent")
    print(f"  status                 - Show connection status")
    print(f"  quit                   - Exit")
    print(f"\n")

    try:
        while True:
            try:
                cmd = await asyncio.get_event_loop().run_in_executor(
                    None, input, f"[{name}]> "
                )

                parts = cmd.strip().split(maxsplit=2)
                if not parts:
                    continue

                action = parts[0].lower()

                if action == 'quit' or action == 'exit':
                    break
                elif action == 'status':
                    print(f"Connected: {agent.transport.is_connected}")
                    print(f"AMID: {agent.amid}")
                elif action == 'lookup' and len(parts) > 1:
                    await agent.lookup(parts[1])
                elif action == 'send' and len(parts) > 2:
                    await agent.send_message(parts[1], {"text": parts[2]})
                else:
                    print(f"Unknown command: {cmd}")

            except EOFError:
                break

    except KeyboardInterrupt:
        print(f"\n")
    finally:
        await agent.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description="AgentMesh Two-Agent Communication Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Terminal 1 - Start Alice as a listener
  python3 examples/two_agents_test.py --name alice --listen

  # Terminal 2 - Start Bob and send to Alice
  python3 examples/two_agents_test.py --name bob --send-to <alice_amid>

  # Interactive mode
  python3 examples/two_agents_test.py --name charlie --interactive
        """
    )

    parser.add_argument(
        '--name', '-n',
        default='agent',
        help='Name for this agent (default: agent)'
    )
    parser.add_argument(
        '--listen', '-l',
        action='store_true',
        help='Run in listener mode (wait for incoming messages)'
    )
    parser.add_argument(
        '--send-to', '-s',
        metavar='AMID',
        help='AMID of the agent to send messages to'
    )
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Run in interactive mode'
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Delete existing identity and start fresh'
    )

    args = parser.parse_args()

    # Clean if requested
    if args.clean:
        import shutil
        agent_dir = TEST_DATA_DIR / args.name
        if agent_dir.exists():
            shutil.rmtree(agent_dir)
            print(f"Cleaned identity for {args.name}")

    # Run the appropriate mode
    if args.listen:
        asyncio.run(run_listener(args.name))
    elif args.send_to:
        asyncio.run(run_sender(args.name, args.send_to))
    elif args.interactive:
        asyncio.run(run_interactive(args.name))
    else:
        parser.print_help()
        print(f"\n Please specify --listen, --send-to <AMID>, or --interactive")


if __name__ == "__main__":
    main()
