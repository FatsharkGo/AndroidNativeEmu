class VirtualFile:

    def __init__(self, name, file_descriptor, name_virt=None):
        self.name = name
        self.name_virt = name_virt
        self.descriptor = file_descriptor
