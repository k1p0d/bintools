__author__ = 'exodus'


from sys import argv
from capstone import *
import pefile
import re

# quick a dirty value for max instruction size in bytes
MAX_INST_SIZE = 15


class OutsideCodeSectionError(Exception):
    pass

class BinFlowDecomposer(object):

    def __init__(self, pe_file, decode_type=CS_MODE_32, parent=False):

        if parent:
            this = parent
        else:
            this = self

        if pe_file[:2] == 'MZ':
            self.pe = pefile.PE(data=pe_file)
        else:
            self.pe = pefile.PE(pe_file)
        self.base_address = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.pe.OPTIONAL_HEADER.ImageBase
        self.history = set()
        self.stack = []
        self.p_actual_offset = 0
        self.p_virtual_offset = self.base_address

        self.current_inst = None

        if decode_type not in (CS_MODE_16, CS_MODE_32, CS_MODE_64):
            raise ValueError("Invalid decode type value: %r" % (decode_type,))

        self.decode_type = decode_type
        self.cs = Cs(CS_ARCH_X86, decode_type)
        self.cs.detail = True

        self.code_section = self.pe.get_section_by_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        self.code = self.pe.__data__[self.code_section.PointerToRawData:self.code_section.PointerToRawData+self.code_section.SizeOfRawData]

        if not self.code:
            return


        self.p_actual_offset = self.pe.get_offset_from_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint) - self.code_section.PointerToRawData


    def __translate_va_to_code_offset(self,va):

        return self.pe.get_offset_from_rva(va - self.pe.OPTIONAL_HEADER.ImageBase) - self.code_section.PointerToRawData

    def _is_code_section_offset(self, va):
        code_section_start = self.pe.OPTIONAL_HEADER.ImageBase + self.code_section.VirtualAddress
        code_section_end = code_section_start + self.code_section.SizeOfRawData

        if va >= code_section_start and va < code_section_end:
            return True

    def __set_offset(self,va):

        if self._is_code_section_offset(va):
            self.p_virtual_offset = va
            self.p_actual_offset = self.__translate_va_to_code_offset(va)
        else:
            raise OutsideCodeSectionError

    def __next_offset(self):

        next_offset = self.current_inst.address + self.current_inst.size

        self.__set_offset(next_offset)

        return next_offset

    def __get_next_offset(self):
        return self.current_inst.address + self.current_inst.size

    def __jump_offset(self, va):

        # set offset
        self.__set_offset(va)

        return va


    def follow(self, inst_count=500):

        while inst_count:


            # break if we have been here then break
            if self.p_virtual_offset in self.history:
                try:

                    offset, inst_count = self.stack.pop()
                except IndexError:
                    break

                self.__set_offset(offset)
                continue

            # decode one insturction
            inst = next(self.cs.disasm(self.code[self.p_actual_offset:self.p_actual_offset+MAX_INST_SIZE],self.p_virtual_offset, 1))

            # set current instruction
            self.current_inst = inst

            yield inst

            # add to history
            self.history.add(inst.address)

            inst_count -= 1

            # process the yield instruction

            jumping_offset = None
            # is it a call ?
            if CS_GRP_CALL in inst.groups:

                p = re.compile(r'(0x[a-f0-9]{2,8})')
                match = p.search(inst.op_str)
                if match:
                    next_offset = int(p.search(inst.op_str).group(0),0)

                    # push the address of the next instruction to the call stack
                    if self._is_code_section_offset(next_offset):

                        # TODO: copy reference of the data to the new instances so the process wont get bigger
                        #c = BinFlowDecomposer(self.pe.__data__,decode_type=self.decode_type)
                        #for i in c.follow(start_va=next_offset,inst_count=inst_count, parent=this):
                        #    yield i

                        self.stack.append((self.__get_next_offset(), inst_count))
                        self.__set_offset(next_offset)
                        continue



            # is it a return?
            elif CS_GRP_RET in inst.groups:
                # so we wont skip another instruction
                try:
                    offset, inst_count = self.stack.pop()
                except IndexError:
                    break
                self.__set_offset(offset)
                continue



            # is it a jump of some kind?
            elif CS_GRP_JUMP in inst.groups:

                p = re.compile(r'(0x[a-f0-9]{2,8})')
                match = p.search(inst.op_str)
                if match:
                    jumping_offset = int(match.group(0),0)
                    if self._is_code_section_offset(jumping_offset):

                        #c = BinFlowDecomposer(self.pe.__data__,decode_type=self.decode_type)
                        #for i in c.follow(start_va=jumping_offset, inst_count=inst_count, parent=this):
                        #    yield i
                        if inst.mnemonic[:3] != 'jmp':
                            self.stack.append((self.__get_next_offset(),inst_count))

                        self.__set_offset(jumping_offset)
                        continue

                    if inst.mnemonic[:3] == 'jmp':
                        try:
                            offset, inst_count = self.stack.pop()
                        except IndexError:
                            break
                        self.__set_offset(offset)
                        continue

            # single step?
            try:
                self.__next_offset()
            except OutsideCodeSectionError:
                try:
                    offset, inst_count = self.stack.pop()
                    self.__set_offset(offset)
                except IndexError:
                    break

