import lief

from . import symbol_resolved

class ELFReader:
    def __init__(self, fpn: str):
        """
        fpn: ELF file path name
        """
        self._fpn = fpn
        self._binary = lief.parse(self._fpn)
        if self._binary.header.file_type != lief.ELF.E_TYPE.DYNAMIC:
            raise NotImplementedError("Only ET_DYN is supported at the moment.")


    def fpn(self) -> str:
        return self._fpn

    def is64(self) -> bool:
        return self._binary.type == lief.ELF.ELF_CLASS.CLASS64

    def get_load(self) -> list[lief.ELF.Segment]:
        seg_loads = [s for s in self._binary.segments if s.type==lief.ELF.SEGMENT_TYPES.LOAD]
        return seg_loads

    def get_so_need(self) -> list[str]:
        return self._binary.libraries

    def get_init_array(self, load_base: int) -> list[int]:
        if self._binary.has(lief.ELF.DYNAMIC_TAGS.INIT_ARRAY):
            secia = self._binary.get_section(".init_array")
            ia_vstart = secia.virtual_address
            ia_entries = secia.size / 4
            init_array = self._binary[lief.ELF.DYNAMIC_TAGS.INIT_ARRAY].array
            if ia_entries != len(init_array):
                raise ValueError(".init_array entries mismatch")
            if 0 in init_array:
                reia = [en for en in self.get_rels() if en.address 
                        in range(ia_vstart, ia_vstart+secia.size)
                            and en.type==int(lief.ELF.RELOCATION_ARM.ABS32)]
                for ent in reia:
                    idx = int((ent.address - ia_vstart)/4)
                    if init_array[idx] == 0:
                        init_array[idx] = ent.symbol.value

            return [fptr+load_base for fptr in init_array if fptr != 0]
        else:
            return []

    def get_init(self, base:int) -> int:
        if self._binary.has(lief.ELF.DYNAMIC_TAGS.INIT):
            return base + self._binary[lief.ELF.DYNAMIC_TAGS.INIT].content
        else:
            return None

    def get_symbols(self) -> list[lief.ELF.Symbol]:
        return list(self._binary.symbols)

    #def get_rels(self) -> dict(str, lief.ELF.Section):
    #    sec_rels = [sec for sec in self._binary.sections if sec.type==lief.ELF.SECTION_TYPES.REL]
    #    return {sec.name: sec for sec in sec_rels}
    def get_rels(self) -> list[lief.ELF.Relocation]:
        return list(self._binary.relocations)


