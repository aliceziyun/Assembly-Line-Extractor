import re
import argparse

def get_addr_from_line(line):
    pattern = r"\b[0-9a-fA-F]+\b"
    matches = re.findall(pattern, line)

    a = matches[0]
    b = matches[1]

    return a,b

def get_load_line_string(addr):
    return "LOAD:"+ ((16-len(addr))*'0') + addr.upper()

def get_hex_string(num, offset):
    tmp = int(num,16) + offset
    return ("{}".format(hex(tmp)))[2:]

class Extractor:
    def __init__(self, output_dir,input_a_dir,input_c_dir,start,end):
        self.output_dir = output_dir
        self.input_assembly_dir = input_a_dir
        self.input_cfg_dir = input_c_dir
        self.start = start
        self.end = end
        self.lines = []

    def dump_line(self,start_addr,end_addr):
        for line_ in self.lines:
            start = get_load_line_string(start_addr)

            possible_start = get_hex_string(start_addr,4)
            possible_start_str = get_load_line_string(possible_start)

            line = line_.decode("utf-8")
            if line.startswith(start) or line.startswith(possible_start_str):
                with open(self.output_dir,"a") as res_file:
                    res_file.write(line)
                    res_file.close()
                    
                if start_addr == end_addr:
                        return "end"

                parts = line.split()
                if len(parts) > 1 and parts[1] == "B":     # cfg changes here
                    return parts[2][4:]
                
                if line.startswith(start):
                    index = self.lines.index(line_)
                    while index < len(self.lines):
                        index = index + 1
                        line = self.lines[index].decode("utf-8")
                        if line.startswith(start):
                            with open(self.output_dir,"a") as res_file:
                                res_file.write(line)
                                res_file.close()
                        else:
                            break
                    start_addr = get_hex_string(start_addr, 4)
                    continue

                elif line.startswith(possible_start_str):   # oops, there may be offset with 8 because of ida
                    start_addr = get_hex_string(start_addr, 8)
                    continue
        return "error"

    def dump_line_from_start_to_end(self,start_addr,end_addr):
        print(f"dump lines in {start_addr.upper()} to {end_addr.upper()}...")
        while True:
            res = self.dump_line(start_addr,end_addr)
            if res == "end":
                return
            if res == "error":
                print("there is an error during extracting...")
                return
            else:
                start_addr = get_hex_string(res,0)
                # print("new start str",start_addr)
                continue

    def extract_assembly(self,start,end):
        print("start extract your assembly...")
        with open(self.input_assembly_dir,"rb") as assembly_file:
            self.lines = assembly_file.readlines()
            assembly_file.close()
        
        with open(self.input_cfg_dir,"rb") as f:
            start_addr = start.upper()
            end_addr = end.upper()
            while True:
                line = f.readline().decode("utf-8")
                if line:
                    current_addr,next_addr = get_addr_from_line(line)
                    if current_addr == "":
                        continue
                    else:
                        self.dump_line_from_start_to_end(start_addr,current_addr)
                        start_addr = next_addr
                        continue
                else:
                    break
                
            self.dump_line_from_start_to_end(start_addr,end_addr)
            print("the program is ended.")

def main():
    parser = argparse.ArgumentParser(
                    prog="Extractor",
                    description='A tool for extracting specific lines from ida dumped assembly files based on your control flow file',
                    epilog='^_^')
    parser.add_argument('-af',dest="input_a_file",metavar='assembly_file',type=str, nargs='?', help='location of your original assembly file')
    parser.add_argument('-cf',dest="input_c_file",metavar='cfg_file',type=str, nargs='?', help='location of your control flow file')
    parser.add_argument('-o',dest="output_file",metavar='output_file',type=str, nargs='?', help='location of file you want to store')
    parser.add_argument('start',metavar='start_addr',type=str, nargs='?', help='start address of assembly')
    parser.add_argument('end',metavar='end_addr',type=str, nargs='?', help='end address of assembly')

    parser.print_help()
    args = parser.parse_args()
    if args.input_a_file == None or args.input_c_file == None:
        print("please specify input file")
        exit(0)

    e = Extractor(args.output_file,args.input_a_file,args.input_c_file,args.start,args.end)
    e.extract_assembly(args.start,args.end)

if __name__ == "__main__":
    main()