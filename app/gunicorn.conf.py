import os

bind = "%s:%s" % (os.environ.get("MSIRB_HOST", "0.0.0.0"), os.environ.get("MSIRB_PORT", "8080"))
workers = 1          # кэши и очистка держатся в памяти процесса
threads = 4
timeout = 900        # загрузка больших MSI
accesslog = "-"
errorlog = "-"
