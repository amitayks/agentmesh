#!/usr/bin/env python3
"""
AgentMesh OpenClaw Skill Setup
Generates keys, creates config directory, and registers with the network.
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from datetime import datetime, timezone

# Add skill directory to path
sys.path.insert(0, str(Path(__file__).parent))

from agentmesh.identity import Identity
from agentmesh.discovery import RegistryClient
from agentmesh.config import Config, DEFAULT_POLICY

AGENTMESH_DIR = Path.home() / ".agentmesh"
KEYS_DIR = AGENTMESH_DIR / "keys"
LOGS_DIR = AGENTMESH_DIR / "logs"
TRANSCRIPTS_DIR = AGENTMESH_DIR / "transcripts"
SESSIONS_DIR = AGENTMESH_DIR / "sessions"

def create_directories():
    """Create the AgentMesh directory structure."""
    print("Creating AgentMesh directories...")

    for directory in [AGENTMESH_DIR, KEYS_DIR, LOGS_DIR, TRANSCRIPTS_DIR, SESSIONS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"  Created: {directory}")

    # Set restrictive permissions on keys directory
    KEYS_DIR.chmod(0o700)

def generate_identity():
    """Generate cryptographic identity."""
    print("\nGenerating cryptographic identity...")

    identity = Identity.generate()

    # Save keys
    keys_file = KEYS_DIR / "identity.json"
    identity.save(keys_file)

    print(f"  AMID: {identity.amid}")
    print(f"  Signing key: {identity.signing_public_key_b64[:20]}...")
    print(f"  Exchange key: {identity.exchange_public_key_b64[:20]}...")
    print(f"  Keys saved to: {keys_file}")

    return identity

def create_default_policy():
    """Create default security policy."""
    print("\nCreating default security policy...")

    policy_file = AGENTMESH_DIR / "policy.json"

    with open(policy_file, 'w') as f:
        json.dump(DEFAULT_POLICY, f, indent=2)

    print(f"  Policy saved to: {policy_file}")

def create_config():
    """Create configuration file."""
    print("\nCreating configuration...")

    config = Config.default()
    config_file = AGENTMESH_DIR / "config.json"

    with open(config_file, 'w') as f:
        json.dump(config.to_dict(), f, indent=2)

    print(f"  Config saved to: {config_file}")

async def register_with_network(identity: Identity):
    """Register this agent with the AgentMesh registry."""
    print("\nRegistering with AgentMesh network...")

    try:
        client = RegistryClient()
        result = await client.register(identity)

        if result.get('success'):
            print(f"  Registered successfully!")
            print(f"  Tier: {result.get('tier', 'anonymous')}")

            # Save registration info
            reg_file = AGENTMESH_DIR / "registration.json"
            with open(reg_file, 'w') as f:
                json.dump({
                    'amid': identity.amid,
                    'tier': result.get('tier', 'anonymous'),
                    'registered_at': datetime.now(timezone.utc).isoformat(),
                }, f, indent=2)
        else:
            print(f"  Registration failed: {result.get('error', 'Unknown error')}")
            print("  You can still use AgentMesh in offline/anonymous mode.")
    except Exception as e:
        print(f"  Could not connect to registry: {e}")
        print("  You can register later with 'mesh_connect'")

def main():
    """Main installation routine."""
    print("=" * 60)
    print("AgentMesh Skill Installation")
    print("=" * 60)

    # Check if already installed
    if (KEYS_DIR / "identity.json").exists():
        print("\nAgentMesh is already installed!")
        response = input("Do you want to reinstall? This will generate new keys. [y/N] ")
        if response.lower() != 'y':
            print("Installation cancelled.")
            return

    # Create directories
    create_directories()

    # Generate identity
    identity = generate_identity()

    # Create policy
    create_default_policy()

    # Create config
    create_config()

    # Register with network
    asyncio.run(register_with_network(identity))

    print("\n" + "=" * 60)
    print("Installation complete!")
    print("=" * 60)
    print(f"\nYour AgentMesh ID (AMID): {identity.amid}")
    print("\nAvailable commands:")
    print("  mesh_connect    - Connect to the network")
    print("  mesh_send       - Send a message to another agent")
    print("  mesh_search     - Search for agents by capability")
    print("  mesh_status     - Show connection status")
    print("  mesh_dashboard  - Open the owner dashboard")
    print("\nFor help: mesh_help")

if __name__ == "__main__":
    main()
