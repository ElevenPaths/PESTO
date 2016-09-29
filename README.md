PESTO: PE (files) Statistical Tool
====================================

Description
-----------

PESTO is a Python script that extracts and saves in a database some PE file security characteristics or flags
searching for every PE binary in a whole directory, and saving results in a database. 

It checks for architecture flag in the header, and for the following security flags: ASLR, NO_SEH, DEP and CFG. 
Code is clear enough to modify flags and formats to your own needs.

More details and flag explanation in here: 
https://www.slideshare.net/elevenpaths/anlisis-del-nivel-proteccin-antiexploit-en-windows-10

Functionality
-------------

The script just needs a path and a tag. The program will go through the path and subdirectories searching for 
.DLL and .EXE files and extracting the flags in the PE header (thanks to PEfile python library). 

The program requires a tag that will be used as a suffix for logs and database filenames, 
so different analysis can be done in the same directory.

The information provided by the script is:
- Percentage of .DLL and .EXE files with i386, AMD64, IA64 or other architecture.
- Percentage of ASLR, NO_SEH, DEP and CFG flags enabled or disabled in the headers.
- After finishing the analysis it will prompt to export results in a SQL or CSV format. 

It will create as well a .db file which is a sqlite file with the information collected.
