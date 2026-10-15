# Terminal demo for the README. Regenerate with:  make demo
# Records the real CLI; nothing is staged.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 900
Set Padding 18
Set Theme "GitHub Dark"
Set TypingSpeed 30ms

Hide
Type "export PATH=/opt/authz-proof:$PATH PS1='$ ' && cd /vhs/examples/drive && clear"
Enter
Show

Type "authz-proof diff schema.zed schema-refactor.zed relationships.txt --fail-on-gain"
Enter
Sleep 9s

Type "clear"
Enter
Sleep 300ms

Type "authz-proof diff schema.zed schema-reordered.zed relationships.txt --fail-on-gain   # same rules, reordered"
Enter
Sleep 3s

Type "authz-proof validate schema-no-parens.zed"
Enter
Sleep 6s

Type "clear"
Enter
Sleep 300ms

Type "authz-proof check schema.zed relationships.txt document:payroll#view@user:bob"
Enter
Sleep 5s

Type "authz-proof mutants --seeds 300"
Enter
Sleep 14s
