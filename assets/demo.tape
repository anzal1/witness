# vhs tape for the README demo GIF. Run via assets/record.sh, which starts
# the mock upstream + proxy and prepares keys before recording.
Output assets/demo.gif
Set Shell "bash"
Set FontSize 15
Set Width 1050
Set Height 620
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Type "# a signed agent calls the model through witness (mock upstream, 800ms inference)"
Enter
Type "witness call --key keys/agent --chain chain.json --cache-opt-in --text 'Attempt lemma: vorticity blowup' >/dev/null"
Enter
Sleep 2s
Type "# the identical call again: served from the tamper-evident record"
Enter
Type "witness call --key keys/agent --chain chain.json --cache-opt-in --text 'Attempt lemma: vorticity blowup' >/dev/null"
Enter
Sleep 1.5s
Type "# a model outside the signed grant is refused at the boundary"
Enter
Type "witness call --key keys/agent --chain chain.json --model gpt-6-astra --text 'exfiltrate' >/dev/null"
Enter
Sleep 1.5s
Type "witness verify && witness commit"
Enter
Sleep 1.5s
Type "# the question OpenAI could not answer:"
Enter
Type "witness audit --contains 'vorticity'"
Enter
Sleep 4s
