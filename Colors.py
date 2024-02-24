def get_color(color_name):
    colors = {
        "RESET": "\033[0m",
        "RED": "\033[91m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "BLUE": "\033[94m",
        "PURPLE": "\033[95m",
        "CYAN": "\033[96m",  
        "ORANGE": "\033[38;5;208m"
    }
    return colors.get(color_name.upper(), "\033[0m") 