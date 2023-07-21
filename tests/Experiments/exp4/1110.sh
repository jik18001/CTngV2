#!/bin/bash

SESSION="network"

# Start a new tmux session
tmux new-session -d -s $SESSION

# Create a new window for each command
tmux new-window -n "network_ca_1" go run Test1.go CA 1
tmux new-window -n "network_ca_2" go run Test1.go CA 2
tmux new-window -n "network_ca_3" go run Test1.go CA 3
tmux new-window -n "network_ca_4" go run Test1.go CA 4
tmux new-window -n "network_ca_5" go run Test1.go CA 5
tmux new-window -n "network_ca_6" go run Test1.go CA 6
tmux new-window -n "network_ca_7" go run Test1.go CA 7
tmux new-window -n "network_ca_8" go run Test1.go CA 8
tmux new-window -n "network_ca_9" go run Test1.go CA 9
tmux new-window -n "network_ca_10" go run Test1.go CA 10
tmux new-window -n "network_logger_1" go run Test1.go Logger 1
tmux new-window -n "network_logger_2" go run Test1.go Logger 2
tmux new-window -n "network_logger_3" go run Test1.go Logger 3
tmux new-window -n "network_logger_4" go run Test1.go Logger 4
tmux new-window -n "network_logger_5" go run Test1.go Logger 5
tmux new-window -n "network_logger_6" go run Test1.go Logger 6
tmux new-window -n "network_logger_7" go run Test1.go Logger 7
tmux new-window -n "network_logger_8" go run Test1.go Logger 8
tmux new-window -n "network_logger_9" go run Test1.go Logger 9
tmux new-window -n "network_logger_10" go run Test1.go Logger 10
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