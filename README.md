# Assembly-Line-Extractor
A mini tool for extracting specific lines from ida dumped assembly files based on control flow

### usage
```
python assembly_extractor.py -af [assembly_file] -cf [cfg_file] -o [output_file] start_addr end_addr
```
##### warning
1. `start_addr` and `end_addr` is the start address and end address of the assembly fragment you provide and must be in **hex format**
2. your assembly fragment should be consistent

### assembly file
an assembly file should be fully copied from ida and be like this:
```
LOAD:000000000001577C                 LDP             X20, X19, [SP,#0x60+var_10]
LOAD:0000000000015780                 LDP             X22, X21, [SP,#0x60+var_20]
LOAD:0000000000015784                 LDP             X24, X23, [SP,#0x60+var_30]
...
```

or like this:
```
```

### control flow file
you can write the control flow file in your own format

but it should include current addresss and next address the program will jump to in one line

recommendated formats are like these:
1. addr offset is `current_addr`, next addr is `next_addr`
2. current:`current_addr`, next:`next_addr`
