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
        # As the doc mentioned, binary's getter only return the first one:
        #  https://lief-project.github.io/doc/latest/api/python/elf.html#binary
        if self._binary.has(lief.ELF.DYNAMIC_TAGS.INIT_ARRAY):
            return [fptr+load_base for fptr in self._binary[lief.ELF.DYNAMIC_TAGS.INIT_ARRAY].array]
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


