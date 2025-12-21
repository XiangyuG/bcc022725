#!/usr/bin/env bash
set -e

apt-get update
apt-get install -y python3-pip
sudo apt install -y git build-essential libssl-dev

sudo apt install python3-kubernetes
sudo apt install python3-pyroute2