#!/bin/python3

#This script is used for generating all the tests.

def scriptGen(A,B,C,D,E):
	script = "#!/bin/bash\n"
	script += "head -c 16007 /dev/urandom > testfile\n"
	if A == 1:
		script += "head -c 16 /dev/urandom > testkey\n"
	elif A == 2:
		script += "head -c 24 /dev/urandom > testkey\n"
	elif A == 3:
		script += "head -c 32 /dev/urandom > testkey\n"
	script += "\n"
	script += "\n./aes_enc -i testfile -k testkey -u 1 "
	if A == 1:
		script += "-t 1 "
	elif A == 2:
		script += "-t 2 "
	elif A == 3:
		script += "-t 3 "

	if B == 1:
		script += "-s "
	if C == 1:
		script += "-f "
	script += "\n"
	script += "./aes_dec -i testfile.aes -k testkey -u 1 "
	if D == 1:
		script += "-s "
	if E == 1:
		script += "-f "
	script += "\n"
	script += "original=$(sha256sum testfile | cut -d\" \" -f1)\n"
	script += "tested=$(sha256sum testfile.aes.decrypted | cut -d\" \" -f1)\n"
	script += "rm testfile testfile.aes testfile.aes.decrypted testkey\n"
	script += "if [ \"$original\" == \"$tested\" ]; then\n"
	script += "\texit 0\n"
	script += "else\n"
	script += "\texit 1\n"
	script += "fi"
	return script

for A in range(1,4):
	for B in range(2):
		for C in range(2):
			for D in range(2):
				for E in range(2):
#					print(f"\t\ttests/test{A}{B}{C}{D}{E}.sh \\")

					with open(f"test{A}{B}{C}{D}{E}.sh","w") as file:
						file.write(scriptGen(A,B,C,D,E))

#                                        print(scriptGen(A,B,C,D,E))
