#!/bin/bash

sudo tc qdisc del dev lo root
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=128
sudo sysctl -w net.core.somaxconn=128