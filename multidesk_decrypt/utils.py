from argparse import HelpFormatter


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, indent_increment=2, max_help_position=7, width=None)

    def _format_action(self, action):
        result = super(CustomHelpFormatter, self)._format_action(action) + "\n"

        if "show this help message and exit" in result:
            result = result.replace("show", "Show", 1)

        return result
