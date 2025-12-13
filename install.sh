#!/usr/bin/env bash
set -e

apt-get update
apt-get install -y python3-pip

# Install specific version of pyroute2
pip3 install "pyroute2<0.7.0"