# Record with: docs/demo-setup.sh && vhs docs/demo.tape
Output docs/demo.gif

Set Shell bash
Set FontSize 19
Set Width 960
Set Height 640
Set Padding 12
Set Theme "Dracula"
Set TypingSpeed 35ms

Hide
Type "/tmp/egdemo/start.sh" Enter
Sleep 1s
Show

Type "env-ghost guard -q .env &" Enter
Sleep 1s
Enter
Sleep 400ms
Type "cat .env" Enter
Sleep 2s
Type "npm install   # bin/npm is a stub that runs cat .env" Enter
Sleep 2.5s
Type "kill %1" Enter
Sleep 1.5s

Hide
Type "tmux -L egdemo kill-server" Enter
