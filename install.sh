#!/usr/bin/env bash
set -e

apt-get update
apt-get install -y python3-pip
sudo apt install -y git build-essential libssl-dev

# Install specific version of pyroute2
pip3 install "pyroute2<0.7.0"