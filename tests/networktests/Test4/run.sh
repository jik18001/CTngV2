#!/bin/bash

SESSION="test4"

# Start a new tmux session
tmux new-session -d -s $SESSION

# Create a new window for each command
tmux new-window -n "ca1" go run test4.go ca 1
tmux new-window -n "logger1" go run test4.go logger 1
tmux new-window -n "monitor1" go run test4.go monitor 1
tmux new-window -n "monitor2" go run test4.go monitor 2
tmux new-window -n "monitor3" go run test4.go monitor 3
tmux new-window -n "monitor4" go run test4.go monitor 4
tmux new-window -n "gossiper1" go run test4.go gossiper 1
tmux new-window -n "gossiper2" go run test4.go gossiper 2
tmux new-window -n "gossiper3" go run test4.go gossiper 3
tmux new-window -n "gossiper4" go run test4.go gossiper 4

# Attach to the tmux session
tmux attach-session -t $SESSION
