#!/bin/bash

SESSION="network"

# Start a new tmux session
tmux new-session -d -s $SESSION

# Create a new window for each command
tmux new-window -n "network_ca_1" go run Test1.go CA 1
tmux new-window -n "network_ca_2" go run Test1.go CA 2
tmux new-window -n "network_ca_3" go run Test1.go CA 3
tmux new-window -n "network_logger_1" go run Test1.go Logger 1
tmux new-window -n "network_logger_2" go run Test1.go Logger 2
tmux new-window -n "network_logger_3" go run Test1.go Logger 3
tmux new-window -n "network_monitor_1" go run Test1.go Monitor 1
tmux new-window -n "network_monitor_2" go run Test1.go Monitor 2
tmux new-window -n "network_gossiper_1" go run Test1.go Gossiper 1
tmux new-window -n "network_gossiper_2" go run Test1.go Gossiper 2
# Attach to the tmux session
tmux attach-session -t $SESSION