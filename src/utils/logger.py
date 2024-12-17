import logging

class LoggerFactory:
    
    @staticmethod
    def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
        """
        Creates and returns a logger object with the specified name and log level.
        
        Args:
            name (str): The name of the logger.
            level (int): The log level for the logger.
        """
        logger = logging.getLogger(name)
        logger.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        return logger