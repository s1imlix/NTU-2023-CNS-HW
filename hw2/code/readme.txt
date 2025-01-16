=== Note === 
All the code below may encounter EOFError due to incomplete server response. Just run the code again and it should work fine.

=== Instruction ===
code4.py
- This code is only for factorization of server's RSA modulus n and generate the private key
- The commands ran is included in report.pdf and the necessary files are in code/ folder
- However, simply running the openssl s_client connect command suffices with necessary files in code/ folder

code5.py 
- Simply run with python3 code5.py
- Problem d is solved directly after problem c

code6[a-d].py
- Simply run with python3 code6[a-d].py 
- Require code6b_lib.py, cipher.py and public.py

=== tl;dr ===
Install necessary packages with requirement.txt and the code should work fine with the following files.
List of extra files in code/ are client.crt, client.csr, client.key, private.key, root.crt, root.key, server.crt, server.key, grabber.py
