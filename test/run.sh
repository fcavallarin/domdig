#!/bin/bash

WD=$( cd "$(dirname "$(readlink $0 || echo $0)")" ; pwd -P )
command -v tmux >/dev/null || { echo "tmux is required"; exit 1; }
TESTS="$1"
tmux kill-session -t domdigltest > /dev/null 2>&1
tput setaf 2
echo "Tests started at "`date` 
tput sgr0
echo -ne "" > $WD/test-results.log
tmux new-session -d -s domdigltest "python3 -m http.server 9092 -b 127.0.0.1 -d $WD/testpages"
sleep 1


TEST_CMD="\
node $WD/unit.js $TESTS > $WD/test-results.log 2>&1 ;\
tmux kill-session -t domdigltest \
"
tmux split-window -t domdigltest "$TEST_CMD"

tmux a -t domdigltest  > /dev/null 2>&1
tput setaf 1
cat $WD/test-results.log
tput setaf 2
echo "Tests finished at "`date` 
tput sgr0
rm $WD/test-results.log
exit 0