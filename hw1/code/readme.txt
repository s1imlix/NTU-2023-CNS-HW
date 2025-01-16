=== Note === 
All the code below may encounter EOFError due to incomplete server response. Just run the code again and it should work fine.

=== Instruction ===
code5.py
- Require grabber.py to work
- 5.b is not implemented but solved with online tools
- 5.c require user to manually find readable passphrase
- 5.d require user to manually find readable flag

code6.py 
- 6.a require user to use an online tool to factorize the given number
- Require grabber.py to work
- Require oweiner.py to work

code7*.py
- Require grabber.py to work
- 7-1 may fail (indicated by the progress bar when it reaches the end and no guess is correct) in such case just re-run the code
- If re-running on the same machine do not fix the issue, try running on another machine

code8.py 
- The script get flag of a-c sequentially
- Require two pdf files with colliding SHA-1 hash, provided as a.pdf and b.pdf in parent directory
- For 8.a user is prompted the two colliding pdfs' filename, just input a.pdf and b.pdf
- For 8.c binary file ./hash_extender is required 

=== tl;dr ===
Install necessary packages with requirement.txt and the code should work fine with the following files.
List of extra files in code/ are a.pdf, b.pdf, hash_extender, oweiner.py, grabber.py

