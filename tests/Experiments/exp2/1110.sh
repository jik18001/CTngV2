#!/bin/bash

SESSION="network"

# Start a new tmux session
tmux new-session -d -s $SESSION

# Create a new window for each command
tmux new-window -n "network_ca_1" go run Test1.go CA 1
tmux new-window -n "network_logger_1" go run Test1.go Logger 1
tmux new-window -n "network_monitor_1" go run Test1.go Monitor 1
tmux new-window -n "network_monitor_2" go run Test1.go Monitor 2
tmux new-window -n "network_monitor_3" go run Test1.go Monitor 3
tmux new-window -n "network_monitor_4" go run Test1.go Monitor 4
tmux new-window -n "network_monitor_5" go run Test1.go Monitor 5
tmux new-window -n "network_monitor_6" go run Test1.go Monitor 6
tmux new-window -n "network_monitor_7" go run Test1.go Monitor 7
tmux new-window -n "network_monitor_8" go run Test1.go Monitor 8
tmux new-window -n "network_monitor_9" go run Test1.go Monitor 9
tmux new-window -n "network_monitor_10" go run Test1.go Monitor 10
tmux new-window -n "network_gossiper_1" go run Test1.go Gossiper 1
tmux new-window -n "network_gossiper_2" go run Test1.go Gossiper 2
tmux new-window -n "network_gossiper_3" go run Test1.go Gossiper 3
tmux new-window -n "network_gossiper_4" go run Test1.go Gossiper 4
tmux new-window -n "network_gossiper_5" go run Test1.go Gossiper 5
tmux new-window -n "network_gossiper_6" go run Test1.go Gossiper 6
tmux new-window -n "network_gossiper_7" go run Test1.go Gossiper 7
tmux new-window -n "network_gossiper_8" go run Test1.go Gossiper 8
tmux new-window -n "network_gossiper_9" go run Test1.go Gossiper 9
tmux new-window -n "network_gossiper_10" go run Test1.go Gossiper 10
# Attach to the tmux session
tmux attach-session -t $SESSION