#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-09-15 20:54:10
# @Author  : nforest@outlook.com

import os
import re
import sys
import time
import struct

#////////////////////////////////////////////////////////////////////////////////////////////

try:
    import idaapi
except:
    idaapi = None

radare2 = True if 'R2PIPE_IN' in os.environ else False


#////////////////////////////////////////////////////////////////////////////////////////////

kallsyms = {
            'bits'          :0,
            'arch'          :"arm",
            'is_big_endian' : False, #FIXME: we need to guess this value at very beginning
            '_start'        :0,
            'numsyms'        :0,
            'address'       :[],
            'type'          :[],
            'name'          :[],
            'address_table'     : 0,
            'name_table'        : 0,
            'type_table'        : 0,
            'token_table'       : 0,            
            'table_index_table' : 0,
            }

#TODO: guess little/big endian first
def INT(offset, vmlinux):
    bytes = kallsyms['bits'] / 8
    s = vmlinux[offset:offset+bytes]
    f = 'I' if bytes==4 else 'Q'
    (num,) = struct.unpack(f, s)
    return num

def INT32(offset, vmlinux):
    s = vmlinux[offset:offset+4]
    (num,) = struct.unpack('I', s)
    return num

def INT64(offset, vmlinux):
    s = vmlinux[offset:offset+8]
    (num,) = struct.unpack('Q', s)
    return num

def SHORT(offset, vmlinux):
    s = vmlinux[offset:offset+2]
    (num,) = struct.unpack('H', s)
    return num  

def STRIPZERO(offset, vmlinux, step=4):
    NOTZERO = INT32 if step==4 else INT
    for i in xrange(offset,len(vmlinux),step):
        if NOTZERO(i, vmlinux):
            return i

#//////////////////////

def do_token_index_table(kallsyms , offset, vmlinux):
    kallsyms['token_index_table'] = offset  
    print '[+]kallsyms_token_index_table = ', hex(offset)

def do_token_table(kallsyms, offset, vmlinux):
    kallsyms['token_table'] = offset    
    print '[+]kallsyms_token_table = ', hex(offset)

    for i in xrange(offset,len(vmlinux)):
        if SHORT(i,vmlinux) == 0:
            break
    for i in xrange(i, len(vmlinux)):
        if ord(vmlinux[i]):
            break
    offset = i-2

    do_token_index_table(kallsyms , offset, vmlinux)

def do_marker_table(kallsyms, offset, vmlinux):
    kallsyms['marker_table'] = offset   
    print '[+]kallsyms_marker_table = ', hex(offset)

    offset += (((kallsyms['numsyms']-1)>>8)+1)*(kallsyms['bits']/8)
    offset = STRIPZERO(offset, vmlinux)

    do_token_table(kallsyms, offset, vmlinux)


def do_type_table(kallsyms, offset, vmlinux):
    flag = True
    for i in xrange(offset,offset+256*4,4):
        if INT(i, vmlinux) & ~0x20202020 != 0x54545454:
            flag = False
            break

    if flag:
        kallsyms['type_table'] = offset

        while INT(offset, vmlinux):
            offset += (kallsyms['bits']/8)
        offset = STRIPZERO(offset, vmlinux)
    else:
        kallsyms['type_table'] = 0
    
    print '[+]kallsyms_type_table = ', hex(kallsyms['type_table'])

    offset -= (kallsyms['bits']/8)
    do_marker_table(kallsyms, offset, vmlinux)
            
def do_name_table(kallsyms, offset, vmlinux):
    kallsyms['name_table'] = offset 
    print '[+]kallsyms_name_table = ', hex(offset)

    for i in xrange(kallsyms['numsyms']):
        length = ord(vmlinux[offset])
        offset += length+1
    while offset%4 != 0:
        offset += 1
    offset = STRIPZERO(offset, vmlinux)

    do_type_table(kallsyms, offset, vmlinux)

    # decompress name and type
    name_offset = 0
    for i in xrange(kallsyms['numsyms']):
        offset = kallsyms['name_table']+name_offset
        length = ord(vmlinux[offset])

        offset += 1
        name_offset += length+1

        name = ''
        while length:
            token_index_table_offset = ord(vmlinux[offset])
            xoffset = kallsyms['token_index_table']+token_index_table_offset*2
            token_table_offset = SHORT(xoffset, vmlinux)
            strptr = kallsyms['token_table']+token_table_offset

            while ord(vmlinux[strptr]):
                name += '%c' % ord(vmlinux[strptr])
                strptr += 1

            length -= 1
            offset += 1

        if kallsyms['type_table']:
            kallsyms['type'].append('X')
            kallsyms['name'].append(name)
        else:
            kallsyms['type'].append(name[0])
            kallsyms['name'].append(name[1:])

def do_guess_arch(kallsyms, vmlinux):
    """guess arch by symbol name"""
    arm_count = 0 
    mips_count = 0
    x86_count = 0
    for i in xrange(kallsyms['numsyms']):
        if kallsyms['name'][i].startswith("arm"):
            arm_count += 1
        if kallsyms['name'][i].startswith("mips"):
            mips_count += 1
        if kallsyms['name'][i].startswith("x86_"):
            x86_count += 1
    if arm_count == max(arm_count, mips_count, x86_count):
        kallsyms["arch"] = "arm"
    if mips_count == max(arm_count, mips_count, x86_count):
        kallsyms["arch"] = "mips"
    if x86_count == max(arm_count, mips_count, x86_count):
        kallsyms["arch"] = "x86"


def do_guess_start_address(kallsyms, vmlinux): 
    _startaddr_from_xstext = None
    _startaddr_from_banner = None
    _startaddr_from_processor = None
    _startaddr_from_prologue = None
    
    for i in xrange(kallsyms['numsyms']):
        if kallsyms['name'][i] in ['_text', 'stext', '_stext', '_sinittext', '__init_begin']:
            if hex(kallsyms['address'][i]):
                if _startaddr_from_xstext is None or kallsyms['address'][i]<_startaddr_from_xstext:
                    _startaddr_from_xstext = kallsyms['address'][i]
        
        elif kallsyms['name'][i] == 'linux_banner':
            linux_banner_addr = kallsyms['address'][i]
            linux_banner_fileoffset = vmlinux.find('Linux version ')
            if linux_banner_fileoffset:
                _startaddr_from_banner = linux_banner_addr - linux_banner_fileoffset

        elif kallsyms['name'][i] == '__lookup_processor_type_data':
            lookup_processor_addr = kallsyms['address'][i]

            step = kallsyms['bits'] / 8
            if kallsyms['bits'] == 32 and kallsyms["arch"] == "arm":
                addr_base = 0xC0008000
            elif kallsyms['bits'] == 32:
                addr_base = 0x80008000 # TODO: I'n not sure how it looks like in mips and x86, I see a case that mips kernel starts from 0x8000?????
            else:
                addr_base = 0xffffff8008080000
        
            for i in xrange(0,0x100000,step):
                _startaddr_from_processor = addr_base + i
                fileoffset = lookup_processor_addr - _startaddr_from_processor
                if fileoffset+step > len(vmlinux):
                    continue
                if lookup_processor_addr == INT(fileoffset, vmlinux):
                    break

            if _startaddr_from_processor == _startaddr_from_processor+0x100000:
                _startaddr_from_processor = 0

    if _startaddr_from_banner is None:#this trick takes a longer time...
        print "[!] be patient.. we need more time to find base address..."
        if kallsyms["arch"] == "mips" and kallsyms["bits"] == 32 and kallsyms["is_big_endian"]:
            prologue = "27 bd ff ??"#mipsel addui sp, sp, -xxxxx
        elif kallsyms["arch"] == "mips" and kallsyms["bits"] == 32 and not kallsyms["is_big_endian"]:
            prologue = "?? ff bd 27"#mips   sub sp, sp, xxxxx
        elif kallsyms["arch"] == "arm" and kallsyms["bits"] == 32 and not kallsyms["is_big_endian"]:
            prologue = "0d c0 a0 e1 ?? ?? 2d e9"#mov r12, sp; stm sp!, {xxx, xxx, xxx, xxx}
        elif kallsyms["arch"] == "x86" and kallsyms["bits"] == 64 and not kallsyms["is_big_endian"]:
            prologue = "55 48 89 d5"#push rbp; mov rbp, rsp; #FIXME: not tested
        elif kallsyms["arch"] == "x86" and kallsyms["bits"] == 32 and not kallsyms["is_big_endian"]:
            prologue = "55 89 e5"#push ebp; mov ebp, esp; #FIXME: not tested
        if prologue is not None:
            import random 
            prologue = prologue.replace(" ", "")
            l = len(prologue)/2
            prologue_offset = []
            offset = 0

            #fina all offset that match prologue
            while offset < len(vmlinux) - l:
                hexx = vmlinux[offset:offset+l].encode("hex")
                if all(map(lambda t:t[0] == "?" or t[0] == t[1], zip(prologue, hexx))):
                    prologue_offset.append(offset)
                offset += 1

            base_vote = {}
            #random.shuffle(prologue_offset)
            prologue_offset = prologue_offset[:500:5]# we chose 100 prolog, for performance
            for i in xrange(kallsyms['numsyms']):
                addr = kallsyms['address'][i]
                for offset in prologue_offset:
                    base = addr - offset
                    if base < 0:
                        break
                    if base_vote.get(base) is None:
                        base_vote[base] = 0
                    base_vote[base] += 1
             
            best = 0
            for addr, count in base_vote.items():
                if count > best:
                    _startaddr_from_prologue = addr
                    best = count
    start_addrs = [_startaddr_from_banner, _startaddr_from_prologue, _startaddr_from_processor, _startaddr_from_xstext]
    if kallsyms['bits']==64 and _startaddr_from_banner!=_startaddr_from_xstext:
         start_addrs.append( 0xffffff8008000000 + INT(8, vmlinux) )

    # print '[+]kallsyms_guess_start_addresses = ',  hex(0xffffff8008000000 + INT(8, vmlinux)) if kallsyms['bits']==64 else '', hex(_startaddr_from_banner), hex(_startaddr_from_processor), hex(_startaddr_from_xstext)

    for addr in start_addrs:
        if addr is None:
            continue
        #if addr % 0x1000 == 0: #some vmlinux do not align to 0x1000....
        kallsyms['_start']= addr
        break
    else:
        assert False,"  [!]kernel start address error..."

    return kallsyms['_start']

def do_offset_table(kallsyms, start, vmlinux):
    # aarch64 only!
    step = 4    # this is fixed step

    kallsyms['address'] = []
    prev_offset = 0
    relative_base = 0xffffff8008080000

    # status
    #   0: looking for 1st 00 00 00 00
    #   1: looking for 2nd 00 00 00 00
    #   2: looking for non-zero ascending offset seq
    status = 0

    for i in xrange(start, len(vmlinux), step):
        offset = INT32(i, vmlinux)
        # print hex(i + 0xffffff8008080000), hex(offset)

        if status == 0:
            if offset == 0:
                kallsyms['address'].append(relative_base)
                status = 1
            else:
                return 0
        elif status == 1:
            if offset == 0:
                kallsyms['address'].append(relative_base)
                status = 2
            else:
                return 1
        elif status == 2:
            if (offset > 0) and (offset >= prev_offset):
                kallsyms['address'].append(relative_base + offset)
                prev_offset = offset
            else:
                return (i - start) / step

    return 0

def do_address_table(kallsyms, offset, vmlinux):
    step = kallsyms['bits'] / 8
    if kallsyms['bits'] == 32:
        addr_base = 0x80000000
    else:
        addr_base = 0xffffff8008000000

    kallsyms['address'] = []
    prev_addr = 0
    for i in xrange(offset, len(vmlinux), step):
        addr = INT(i, vmlinux)
        if addr < addr_base:
            return (i-offset)/step
        elif addr < prev_addr:
            return (i-offset)/step
        else:
            kallsyms['address'].append(addr)
            prev_addr = addr

    return 0

def do_kallsyms(kallsyms, vmlinux):
    step = kallsyms['bits'] / 8
    min_numsyms = 4000

    offset = 0
    vmlen  = len(vmlinux)
    is_offset_table = 0

    while offset+step < vmlen:
        num = do_address_table(kallsyms, offset, vmlinux)
        if num > min_numsyms:
            kallsyms['numsyms'] = num
            break
        else:
            offset += (num+1)*step

    if kallsyms['numsyms'] == 0:
        print '[!]could be offset table...'
        is_offset_table = 1
        # offset = 0x1280000
        offset = 0
        step = 4
        while offset+step < vmlen:
            num = do_offset_table(kallsyms, offset, vmlinux)
            if num > min_numsyms:
                kallsyms['numsyms'] = num
                break
            else:
                offset += (num+1) * step
        step = kallsyms['bits'] / 8 # recover normal step


    if kallsyms['numsyms'] == 0:
        print '[!]lookup_address_table error...'
        return
 
    print '[+]numsyms: ', kallsyms['numsyms']

    kallsyms['address_table'] = offset  
    print '[+]kallsyms_address_table = ', hex(offset)

    if is_offset_table == 0:
        offset += kallsyms['numsyms']*step
        offset = STRIPZERO(offset, vmlinux, step)
    else:
        offset += kallsyms['numsyms']*4
        offset = STRIPZERO(offset, vmlinux, 4)
        offset += step  # skip kallsyms_relative_base
        offset = STRIPZERO(offset, vmlinux, 4)
    num = INT(offset, vmlinux)
    offset += step


    print '[+]kallsyms_num = ', kallsyms['numsyms'], num
    if abs(num-kallsyms['numsyms']) > 128:
            kallsyms['numsyms'] = 0
            print '  [!]not equal, maybe error...'    
            return

    if num > kallsyms['numsyms']:
        for i in xrange(kallsyms['numsyms'],num):
            kallsyms['address'].insert(0,0)
    kallsyms['numsyms'] = num

    offset = STRIPZERO(offset, vmlinux)
    do_name_table(kallsyms, offset, vmlinux)
    do_guess_arch(kallsyms, vmlinux)
    do_guess_start_address(kallsyms, vmlinux)
    print '[+]kallsyms_start_address = ', hex(kallsyms['_start'])
    return

def do_get_bits(kallsyms, vmlinux):
    def fuzzy_arm64(vmlinux):
        step = 8
        offset = 0
        vmlen  = len(vmlinux) - len(vmlinux)%8
        addr_base = 0xffffff8008000000
        while offset+step < vmlen:
          for i in xrange(offset, vmlen, step):
                if INT64(i, vmlinux) < addr_base:
                    addrnum = (i-offset)/step
                    if addrnum > 10000:
                        return True
                    else:
                        offset = i+step
        return False

    if re.search('ARMd', vmlinux[:0x200]):
        kallsyms['bits'] = 64
    elif fuzzy_arm64(vmlinux):
        kallsyms['bits'] = 64
    else:
        kallsyms['bits'] = 32

    print '[+]kallsyms_bits = ', kallsyms['bits']

def print_kallsyms(kallsyms, vmlinux):
    buf = '\n'.join( '%x %c %s'%(kallsyms['address'][i],kallsyms['type'][i],kallsyms['name'][i]) for i in xrange(kallsyms['numsyms']) ) 
    # open('kallsyms','w').write(buf)
    print buf

#////////////////////////////////////////////////////////////////////////////////////////////
# IDA Pro Plugin Support

def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # ida 7+ compatibility, n is filename
    # we support only one format per file
    if isinstance(n, (int, long)):
        if n > 0:
            return 0

    # magic = li.read(8)
    # if magic != 'ANDROID!':
    #     return 0

    return "Android/Linux Kernel Image(ARM)"

def load_file(li, neflags, format):
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    li.seek(0)
    vmlinux = li.read(li.size())

    do_get_bits(kallsyms, vmlinux)
    do_kallsyms(kallsyms, vmlinux)
    # print_kallsyms(kallsyms, vmlinux)
    if kallsyms['arch'] == 'arm':
        idaapi.set_processor_type('arm', idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)
    elif kallsyms['arch'] == 'mips' and not kallsyms['is_big_endian']:
        idaapi.set_processor_type('mipsl', idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)
    elif kallsyms['arch'] == 'mips' and not kallsyms['is_big_endian']:
        idaapi.set_processor_type('mipsb', idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)
    elif kallsyms['arch'] == 'x86':
        idaapi.set_processor_type('metapc', idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)#NOT tested

    if kallsyms['bits'] == 64:
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

    li.file2base(0, kallsyms['_start'], kallsyms['_start']+li.size(), True)

    s = idaapi.segment_t()
    s.bitness = kallsyms['bits'] / 32
    s.startEA = kallsyms['_start']
    s.endEA = kallsyms['_start']+li.size()
    idaapi.add_segm_ex(s,".text","CODE",idaapi.ADDSEG_OR_DIE)
    
    for i in xrange(kallsyms['numsyms']):
        if kallsyms['type'][i] in ['t','T']:
            idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 1)
        else:
            idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 0)

    print "Android/Linux vmlinux loaded..."
    return 1

#////////////////////////////////////////////////////////////////////////////////////////////
# Radare2 Plugin Support

def r2():
    r2p = r2pipe.open()
    info = r2p.cmdj("ij")
    with open(info["core"]["file"], 'rb') as f:
            vmlinux = f.read()

    do_get_bits(kallsyms, vmlinux)
    do_kallsyms(kallsyms, vmlinux)
    # print_kallsyms(kallsyms, vmlinux)

    if kallsyms['numsyms'] == 0:
        print '[!]get kallsyms error...'
        return 0

    r2p.cmd("e asm.arch = arm")
    r2p.cmd("e asm.bits = %d" % kallsyms['bits'])

    siol_map = r2p.cmdj("omj")[0]["map"]
    set_baddr = "omr " + str(siol_map) + " " + str(kallsyms["_start"])
    r2p.cmd(set_baddr)

    seg = "S 0 " + str(kallsyms["_start"]) + " " + str(len(vmlinux)) + " .text rx"
    r2p.cmd(seg)

    r2p.cmd("fs symbols")
    for i in xrange(kallsyms['numsyms']):
        if kallsyms["address"][i] == 0:
            continue
        if kallsyms['type'][i] in ['t','T']:
            cmd = "f fcn." + kallsyms["name"][i] + " @ " + str(kallsyms["address"][i])
            r2p.cmd(cmd)
        else:
            cmd = "f sym." + kallsyms["name"][i] + " @ " + str(kallsyms["address"][i])
            r2p.cmd(cmd)

    r2p.cmd("e anal.strings = true")
    r2p.cmd("s " + str(kallsyms["_start"]))

    print "Android/Linux vmlinux loaded..."
    return 1

#////////////////////////////////////////////////////////////////////////////////////////////

def help():
    print 'Usage:  vmlinux.py [vmlinux image]\n'
    exit()

def main(argv):
    if len(argv)!=2:
        help()

    if os.path.exists(argv[1]):
        vmlinux = open(argv[1],'rb').read()
        do_get_bits(kallsyms, vmlinux)
        do_kallsyms(kallsyms, vmlinux)
        if kallsyms['numsyms'] > 0:
            print_kallsyms(kallsyms, vmlinux)
        else:
            print '[!]get kallsyms error...'
    else:
        print '[!]vmlinux does not exist...'

#////////////////////////////////////////////////////////////////////////////////////////////

if idaapi:
    pass
elif radare2:
    import r2pipe
    r2()
else:
    main(sys.argv)
        
