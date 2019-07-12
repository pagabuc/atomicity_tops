from collections import defaultdict
import struct
import sys

if len(sys.argv) != 2:
    print("Usage: python %s ram_smart.lime" % sys.argv[0])
    sys.exit(-1)
    
chunk_file = open('%s' % sys.argv[1],"r")
clean_file = open('%s.clean' % sys.argv[1],"w+")
patches = dict()
addresses = set()
to_cut = 0
while True:
    page_addr = struct.unpack("<Q", chunk_file.read(8) )[0]
    if page_addr & 0xffffffff == 0x4c694d45:
        break

    patch = chunk_file.read(4096)

    if page_addr in addresses: # We should never patch the same address twice...
        print "Twice?!"
        sys.exit(0)

    # print "Patch page: 0x%09x" % (page_addr)
    patches[page_addr] = patch
    to_cut += 4096 + 8

    # For fast checking duplicates..
    addresses.add(page_addr)


patch_counter = len(patches)
print "[+] Total size of patches: %d KB" % (patch_counter*4096 / 1024)

# 'lime_header': [ 0x20, {
#     'magic':     [0x0, ['unsigned int']],
#     'version':   [0x4, ['unsigned int']],
#     'start':     [0x8, ['unsigned long long']],
#     'end':       [0x10, ['unsigned long long']],
#     'reserved':  [0x18, ['unsigned long long']],
# }],

chunk_file.seek(to_cut)
clean_file.seek(0)
s = struct.Struct('< 4s I Q Q Q')
patched_counter = 0
skip = 0
while True:

    read = chunk_file.read(s.size)
    if len(read) != s.size:
        break

    magic, version, range_start, range_end, _ = s.unpack(read)
    if magic != 'EMiL':
        print "We should be done here!"
        break

    print 'Found Range: 0x%09x 0x%09x' % (range_start, range_end)

    clean_file.write(read)
    
    range_size = range_end - range_start
    for i in range(0, range_size, 4096):
        range_page = range_start + i
        if range_page in patches:
            clean_file.write(patches[range_page])
            patched_counter += 1
        else:
            size = min(range_end - range_page + 1, 4096)
            clean_file.write(chunk_file.read(size))        
    
print patch_counter, patched_counter
assert(patch_counter == patched_counter)
chunk_file.close()
clean_file.close()
