# Hypertext O's

## Category

Reverse Engineering

## Public Description

Who needs a local file system anyways.

`qemu-system-i386 -boot n -device e1000,netdev=mynet0 -netdev user,id=mynet0,bootfile=http://CHALLENGE_DOMAIN_HERE`


## Flag

`potluck{th3_1nt3rn3t_1s_my_f1l3syst3m}`


## Build Instructions

Running the `./build.sh` script will create a `build` folder and put all compiled artifacts in that folder.
Building requires `python3`, `java`, `gcc` and `nasm` to be installed.

## Run Instructions

The challenge is meant to be hosted on a Webserver serving the `build` folder as static files over HTTP (not HTTPS!).
For local testing pythons `python3 -m http.server` can be used for example (which serves the server on port 8000), 
and then the challenge can be ran using `qemu-system-i386 -boot n -device e1000,netdev=mynet0 -netdev user,id=mynet0,bootfile=http://127.0.0.1:8000`.

## Intended Writeup

### Surveying

Running the challenge greets you with a selection of `secret_encrypt` and `enter_password`. Navigation between them words with `W` and `S` and `ENTER` to select.

The `secret_encrypt` program encrypts our input and outputs the encrypted hex back to us.
The `enter_password` program asks us for a password and fails us if we enter the wrong one.

Looking into the domain we connect to we can see a IPXE script that makes us boot the `hypertextos` binary on the server.
Either through reversing statically or dynamic analysis we can see that using IPXE's PXE additions this bootloader blob is downloading other files on the server over HTTP.
Specifically `/e410c307/0bafe770` (which contains strings indicating it contains the Javascript engine elk), `/e410c307/c03bc6b3` (which has a big dispatcher loop that looks like a VM) and `/15c93851/844af54e` (which just looks like random data).

### JavaScript

Dynamic inspections shows that the first two files are programs which register themselves to the "Operation System".
The third file is actually decrypted before it is passed to a handler belonging to the Javascript "driver".

Looking at the decrypted file shows that it is in fact obfuscated Javascript. 
The program is responsible for loading other files, notably `/15c93851/3019d862` (secret_encrypt), `/15c93851/8d5e5184` (enter_password) and although not listed when we run it `/15c93851/cd3f3a04` (verify_flag).
(To get `verify_flag` listed a variation of the Konami Code has to be entered `WWSSADADBX` but this is not necessary as the path can be read in the code).


Either through more dynamic file dumping of reusing the existing code or reversing the file decryption (this is harder, it is RC4 with fixed key of hex `0102030405060708`) we can also dump those files.

The `secret_encrypt` program consists out of calling a VM program `/0bbfd16a/054d7b96` with our input and printing back the output as hex.
The `enter_password` program runs a VM program `/0bbfd16a/d1475a3a` to verify our input, specifically it checks if the VM program returns true and if it loads `/15c93851/<input>`.
The `verify_flag` program also calls the VM program `/0bbfd16a/054d7b96` to encrypt our input if it is exactly 38 characters long, and then compares the output against fixed values to verify whether we entered the flag.

### VM

To get further the VM "driver" needs to be Reverse Engineered. It is a pretty standard VM implementation, only notable is that all programs have been completely flattened making reconstruction of the control flow tricky.
It would be recommended to write tooling to lift the VM code (playtesting reported this works very clean in Binary Ninja), but having disassembly (or trace) tooling should be enough.

The `enter_password` program is the most simple and only consists out of a basic length check and checking the individual characters one by one.
The password is `6c523086` and the entered the encrypted flag in hex will be shown (the values are the same as the verify comparison in `verify_flag`) together with a text explaining that this is the encrypted flag.

The `secret_encrypt` program is the actual difficult part of this challenge as it implements a proper encryption algorithm with a fixed key.
In particular it is AES128 with changed round key generation for the first round.

After figuring out this is AES128 it is very possible to just extract those values at runtime though, which will give the hex key `00336699ccff326598cbfe316497cafd`.
The `secret_encrypt` program doesn't implement decryption but given the key and figuring out it is AES128-ECB it is possible to decrypt the given encrypted flag and get the flag.

 

## Credits

Made by Leeky as the submission for organizers for 37C3 Potluck CTF

## License

The original code for this challenge is licensed under the GNU Affero General Public License version 3. (http://www.fsf.org/licensing/licenses/agpl-3.0.html)
This challenge uses many (small) dependencies from various sources, all listed with their respective licenses either in the code and/or in the `OTHER_LICENSES` file.
Most notable is the [elk](https://github.com/cesanta/elk) Javascript engine which is GNU Affero General Public License version 3 licensed.
The Java library [Obfuscat](https://github.com/Pusty/Obfuscat) licensed under the Boost Software License is provided as a compiled binary in the `vm` folder for convenience reasons (and is as of the time of writing this slightly ahead of the public main branch. At the time of the release of this source code the public version should have been updated.)
