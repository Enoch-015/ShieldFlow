#!/usr/bin/env python3
"""
ShieldFlow CLI

Command-line interface for setting up and managing ShieldFlow.

Usage:
    shieldflow setup           - Interactive setup wizard
    shieldflow setup datadog   - Set up Datadog dashboard and monitors
    shieldflow setup docker    - Generate docker-compose.yml for local stack
    shieldflow doctor          - Check environment and dependencies
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional


def get_package_dir() -> Path:
    """Get the shieldflow package directory."""
    return Path(__file__).parent


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check environment and dependencies."""
    print("🩺 ShieldFlow Doctor")
    print("=" * 50)
    
    all_ok = True
    
    # Check Python version
    py_version = sys.version_info
    if py_version >= (3, 9):
        print(f"✓ Python {py_version.major}.{py_version.minor}.{py_version.micro}")
    else:
        print(f"✗ Python {py_version.major}.{py_version.minor} (requires 3.9+)")
        all_ok = False
    
    # Check core dependencies
    deps = [
        ("requests", "Datadog integration"),
        ("redis", "Redis trust store"),
        ("kafka", "Kafka streaming"),
    ]
    
    for module, purpose in deps:
        try:
            __import__(module)
            print(f"✓ {module} - {purpose}")
        except ImportError:
            print(f"○ {module} - {purpose} (optional, not installed)")
    
    # Check environment variables
    print("\n📋 Environment Variables:")
    env_vars = [
        ("DATADOG_API_KEY", "Datadog metrics/logs"),
        ("DATADOG_APP_KEY", "Datadog dashboard setup"),
        ("DD_SITE", "Datadog region (e.g., us5.datadoghq.com)"),
        ("GEMINI_API_KEY", "Gemini AI detection"),
        ("SHIELDFLOW_KAFKA_BOOTSTRAP", "Kafka streaming"),
        ("SHIELDFLOW_KAFKA_TOPIC", "Kafka topic"),
    ]
    
    for var, purpose in env_vars:
        value = os.getenv(var)
        if value:
            display = value[:8] + "..." if len(value) > 10 else value
            print(f"✓ {var}={display} - {purpose}")
        else:
            print(f"○ {var} - {purpose} (not set)")
    
    print("\n" + "=" * 50)
    if all_ok:
        print("✅ ShieldFlow environment looks good!")
    else:
        print("⚠️  Some issues found. See above for details.")
    
    return 0 if all_ok else 1


def cmd_setup_datadog(args: argparse.Namespace) -> int:
    """Set up Datadog dashboard and monitors."""
    print("📊 ShieldFlow Datadog Setup")
    print("=" * 50)
    
    # Check for required environment variables
    api_key = os.getenv("DATADOG_API_KEY")
    app_key = os.getenv("DATADOG_APP_KEY")
    site = os.getenv("DD_SITE") or os.getenv("DATADOG_SITE") or "datadoghq.com"
    
    if not api_key:
        print("❌ DATADOG_API_KEY environment variable not set")
        print("\nTo set up Datadog:")
        print("  1. Get your API key from https://app.datadoghq.com/organization-settings/api-keys")
        print("  2. Get your App key from https://app.datadoghq.com/organization-settings/application-keys")
        print("  3. Set environment variables:")
        print("     export DATADOG_API_KEY=your_api_key")
        print("     export DATADOG_APP_KEY=your_app_key")
        print("     export DD_SITE=us5.datadoghq.com  # if not US1")
        return 1
    
    if not app_key:
        print("❌ DATADOG_APP_KEY environment variable not set")
        print("   App key is required to create dashboards and monitors")
        return 1
    
    try:
        import requests
    except ImportError:
        print("❌ requests library not installed")
        print("   Run: pip install shieldflow[observability]")
        return 1
    
    print(f"Using Datadog site: {site}")
    
    headers = {
        "DD-API-KEY": api_key,
        "DD-APPLICATION-KEY": app_key,
        "Content-Type": "application/json",
    }
    
    # Validate API key
    print("\n🔍 Validating credentials...")
    url = f"https://api.{site}/api/v1/validate"
    resp = requests.get(url, headers=headers, timeout=10)
    
    if resp.status_code != 200:
        print(f"❌ API key validation failed: {resp.status_code}")
        print("   Check your API key and DD_SITE settings")
        return 1
    
    print("✓ API credentials valid")
    
    # Load dashboard JSON
    dashboard_path = get_package_dir() / "datadog" / "dashboard.json"
    if not dashboard_path.exists():
        print(f"❌ Dashboard config not found: {dashboard_path}")
        return 1
    
    with open(dashboard_path) as f:
        dashboard = json.load(f)
    
    # Create dashboard
    print("\n📊 Creating ShieldFlow Dashboard...")
    url = f"https://api.{site}/api/v1/dashboard"
    resp = requests.post(url, headers=headers, json=dashboard, timeout=30)
    
    if resp.status_code == 200:
        data = resp.json()
        dashboard_url = f"https://app.{site}{data['url']}"
        print(f"✓ Dashboard created: {dashboard_url}")
    else:
        print(f"⚠️  Dashboard creation failed: {resp.status_code}")
        print(f"   {resp.text[:200]}")
    
    # Load and create monitors
    monitors_path = get_package_dir() / "datadog" / "monitors.json"
    if monitors_path.exists():
        print("\n🚨 Creating Monitors...")
        with open(monitors_path) as f:
            monitors_data = json.load(f)
        
        url = f"https://api.{site}/api/v1/monitor"
        created = 0
        for monitor in monitors_data.get("monitors", []):
            name = monitor.get("name", "Unknown")
            resp = requests.post(url, headers=headers, json=monitor, timeout=10)
            if resp.status_code == 200:
                print(f"   ✓ {name}")
                created += 1
            elif resp.status_code == 400:
                print(f"   ○ {name} (already exists)")
            else:
                print(f"   ✗ {name}: {resp.status_code}")
        
        print(f"\n   Created {created} monitors")
    
    print("\n" + "=" * 50)
    print("✅ Datadog setup complete!")
    print("\nNext steps:")
    print("1. Open your dashboard in Datadog")
    print("2. Run your ShieldFlow-protected application")
    print("3. Watch detections appear in real-time!")
    
    return 0


def cmd_setup_docker(args: argparse.Namespace) -> int:
    """Generate docker-compose.yml for local stack."""
    print("🐳 ShieldFlow Docker Setup")
    print("=" * 50)
    
    dest = Path.cwd() / "docker-compose.yml"
    
    # Check if already exists in current directory
    if dest.exists():
        print(f"✓ docker-compose.yml already exists at {dest}")
        print("  (Use --force to overwrite)")
        
        # Still ensure Flink Dockerfile is present
        docker_dir = get_package_dir() / "docker"
        flink_src = docker_dir / "flink"
        if flink_src.exists():
            flink_dest = Path.cwd() / "shieldflow" / "docker" / "flink"
            if not flink_dest.exists():
                flink_dest.mkdir(parents=True, exist_ok=True)
                for f in flink_src.iterdir():
                    shutil.copy(f, flink_dest / f.name)
                print(f"✓ Copied Flink Dockerfile to {flink_dest}")
        
        print("\n" + "=" * 50)
        print("✅ Docker setup complete!")
        print("\nTo start the stack:")
        print("  docker-compose up -d")
        print("\nServices:")
        print("  • Redis:  localhost:6380")
        print("  • Kafka:  localhost:19092")
        print("  • Flink:  http://localhost:8081")
        return 0
    
    # Copy docker-compose from package
    docker_dir = get_package_dir() / "docker"
    compose_src = docker_dir / "docker-compose.yml"
    
    # If not in package, use the one from root (for dev)
    if not compose_src.exists():
        compose_src = get_package_dir().parent / "docker-compose.yml"
    
    if not compose_src.exists():
        # Generate a new docker-compose.yml
        compose_content = '''version: "3.8"

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6380:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.3
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    healthcheck:
      test: ["CMD", "bash", "-c", "echo ruok | nc localhost 2181"]
      interval: 10s
      timeout: 5s
      retries: 5

  kafka:
    image: confluentinc/cp-kafka:7.5.3
    depends_on:
      zookeeper:
        condition: service_healthy
    ports:
      - "19092:19092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:19092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
    healthcheck:
      test: ["CMD", "kafka-topics", "--bootstrap-server", "localhost:9092", "--list"]
      interval: 10s
      timeout: 10s
      retries: 10

  flink-jobmanager:
    build:
      context: ./shieldflow/docker/flink
      dockerfile: Dockerfile
    ports:
      - "8081:8081"
    command: jobmanager
    environment:
      FLINK_PROPERTIES: |
        jobmanager.rpc.address: flink-jobmanager

  flink-taskmanager:
    build:
      context: ./shieldflow/docker/flink
      dockerfile: Dockerfile
    depends_on:
      - flink-jobmanager
    command: taskmanager
    environment:
      FLINK_PROPERTIES: |
        jobmanager.rpc.address: flink-jobmanager
        taskmanager.numberOfTaskSlots: 2
'''
        dest = Path.cwd() / "docker-compose.yml"
        with open(dest, "w") as f:
            f.write(compose_content)
        print(f"✓ Created {dest}")
    else:
        dest = Path.cwd() / "docker-compose.yml"
        shutil.copy(compose_src, dest)
        print(f"✓ Copied docker-compose.yml to {dest}")
    
    # Copy Flink Dockerfile
    flink_src = docker_dir / "flink"
    if flink_src.exists():
        flink_dest = Path.cwd() / "shieldflow" / "docker" / "flink"
        flink_dest.mkdir(parents=True, exist_ok=True)
        for f in flink_src.iterdir():
            shutil.copy(f, flink_dest / f.name)
        print(f"✓ Copied Flink Dockerfile to {flink_dest}")
    
    print("\n" + "=" * 50)
    print("✅ Docker setup complete!")
    print("\nTo start the stack:")
    print("  docker-compose up -d")
    print("\nServices:")
    print("  • Redis:  localhost:6380")
    print("  • Kafka:  localhost:19092")
    print("  • Flink:  http://localhost:8081")
    
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    """Interactive setup wizard."""
    if args.component == "datadog":
        return cmd_setup_datadog(args)
    elif args.component == "docker":
        return cmd_setup_docker(args)
    else:
        # Interactive wizard
        print("🛡️  ShieldFlow Setup Wizard")
        print("=" * 50)
        print("\nWhat would you like to set up?\n")
        print("  1. Datadog Dashboard & Monitors")
        print("  2. Docker Stack (Redis, Kafka, Flink)")
        print("  3. Both")
        print("  4. Exit")
        print()
        
        try:
            choice = input("Enter choice [1-4]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSetup cancelled.")
            return 0
        
        if choice == "1":
            return cmd_setup_datadog(args)
        elif choice == "2":
            return cmd_setup_docker(args)
        elif choice == "3":
            ret = cmd_setup_docker(args)
            print()
            ret2 = cmd_setup_datadog(args)
            return ret or ret2
        else:
            print("Setup cancelled.")
            return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="shieldflow",
        description="ShieldFlow: Zero-trust runtime security for LLM agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shieldflow doctor              Check environment and dependencies
  shieldflow setup               Interactive setup wizard
  shieldflow setup datadog       Set up Datadog dashboard
  shieldflow setup docker        Generate docker-compose.yml

Environment Variables:
  DATADOG_API_KEY               Datadog API key for metrics/logs
  DATADOG_APP_KEY               Datadog App key for dashboard creation
  DD_SITE                       Datadog site (e.g., us5.datadoghq.com)
  GEMINI_API_KEY                Enable Gemini AI detection
  SHIELDFLOW_KAFKA_BOOTSTRAP    Kafka bootstrap servers
  SHIELDFLOW_KAFKA_TOPIC        Kafka topic for detections
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Doctor command
    doctor_parser = subparsers.add_parser("doctor", help="Check environment and dependencies")
    doctor_parser.set_defaults(func=cmd_doctor)
    
    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Setup wizard")
    setup_parser.add_argument(
        "component",
        nargs="?",
        choices=["datadog", "docker"],
        help="Component to set up (or interactive if not specified)"
    )
    setup_parser.set_defaults(func=cmd_setup)
    
    # Version
    parser.add_argument("--version", action="version", version="shieldflow 0.1.0")
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
