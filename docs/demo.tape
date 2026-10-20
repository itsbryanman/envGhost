# Record with: vhs docs/demo.tape
Output docs/demo.gif

Set FontSize 16
Set Width 1100
Set Height 600
Set Shell bash

Hide
Type "cd $(mktemp -d) && printf 'STRIPE_KEY=sk_test_FAKEdemo000\nPORT=5432\n' > .env" Enter
Show

Type "env-ghost guard .env &" Enter
Sleep 1s
Type "cat .env" Enter
Sleep 1s
Type "stat -c '%s bytes' .env" Enter
Sleep 1s
Type "env-ghost log -n 3" Enter
Sleep 2s
Type "kill %1" Enter
Sleep 1s
Type "cat .env" Enter
Sleep 2s
