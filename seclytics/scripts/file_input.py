class FileInput(object):
    """Allows us to iterate over stdin like a file"""
    def __init__(self, file):
        self.file = file

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.file.close()

    def __iter__(self):
        return self

    def next(self):
        line = self.file.readline()

        if line is None or line == "":
            raise StopIteration

        return line
