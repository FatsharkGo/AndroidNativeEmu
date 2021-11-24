import logging
logger = logging.getLogger(__name__)

class Module:

    """
    :type filename str
    :type base int
    :type size int
    """
    def __init__(self, filename, address, size, symbols_resolved, init_array=[], entry_point=None):
        self.filename = filename
        self.base = address
        self.size = size
        self.symbols = symbols_resolved
        self.symbol_lookup = dict()
        self.init_array = list(init_array)
        self.entry_point = entry_point

        # Create fast lookup.
        for symbol_name, symbol in self.symbols.items():
            if symbol.address != 0:
                self.symbol_lookup[symbol.address] = (symbol_name, symbol)

    def find_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]
        return None

    def is_symbol_addr(self, addr):
        if addr in self.symbol_lookup:
            return self.symbol_lookup[addr][0]
        elif addr+1 in self.symbol_lookup:
            return self.symbol_lookup[addr+1][0]
        else:
            return None

    def call_init(self, emu):
        for func_ptr in self.init_array:
            logger.info("Calling init_array {} function: 0x{:08X}".format(self.filename, func_ptr))
            emu.call_native(func_ptr)

    def fire_up(self, emu, *argv):
        """
        Call main entry of executable
        """
        if self.entry_point is None:
            logger.warning("No entry point for this module")
            return
        logger.info("Calling entry point 0x{:08X}".format(self.entry_point))
        emu.call_native(self.entry_point, *argv)

