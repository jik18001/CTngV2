#!/usr/bin/env bash

# Sometimes unresponsive CA and Logger

session="test3"
sleep_duration="0.5"

# Create new tmux session named ctng
tmux new -d -s $session

# Create CA/logger window
tmux rename-window ca-logger
tmux split-window -h

# Run CA in first pane and logger in second pane
tmux selectp -t 1
tmux send-keys 'go run test3.go ca 1' C-m
sleep $sleep_duration
tmux selectp -t 2
tmux send-keys 'go run test3.go logger 1' C-m

# Create monitor window
tmux new-window -t 2 -n monitor
tmux split-window -h
tmux split-window -h
tmux split-window -h
tmux select-layout tiled

# Run a monitor in each pane
tmux selectp -t 1
tmux send-keys 'go run test3.go monitor 1' C-m
tmux selectp -t 2
tmux send-keys 'go run test3.go monitor 2' C-m

tmux selectp -t 3
sleep $sleep_duration
tmux send-keys 'go run test3.go monitor 3' C-m
tmux selectp -t 4
sleep $sleep_duration
tmux send-keys 'go run test3.go monitor 4' C-m

# Create gossiper window
tmux new-window -t 3 -n gossiper
tmux split-window -h
tmux split-window -h
tmux split-window -h
tmux select-layout tiled

# Run a gossiper in each pane
tmux selectp -t 1
tmux send-keys 'go run test3.go gossiper 1' C-m
tmux selectp -t 2
tmux send-keys 'go run test3.go gossiper 2' C-m

tmux selectp -t 3
sleep $sleep_duration
tmux send-keys 'go run test3.go gossiper 3' C-m
sleep $sleep_duration
tmux selectp -t 4
tmux send-keys 'go run test3.go gossiper 4' C-m

# Attach to tmux session
tmux attach-session -t $session
