from pathlib import Path

class PySniffManager:
    def __init__(self):
        """Initialize the PySniff manager

        :return:
        """
        self.file_list = []
        self.rule_set = set()
        self.output_format = "screen"
        self.excluded_files = []


    def load_files(self, files):
        """ Load target source files if they exist

        :param files: list of file and directory paths to load
        :return:
        """
        for file in files:
            path = Path(file)

            if path.exists():
                if path.is_dir():
                    self.file_list.extend([p for p in path.iterdir() if p.is_file()])
                else:
                    self.file_list.append(path)
            else:
                self.excluded_files.append((path, "No such file or directory"))

