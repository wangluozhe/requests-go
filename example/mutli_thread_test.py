import time
from threading import Thread

import requests_go


def main(num):
    response = requests_go.get(url="https://www.baidu.com", tls_config=requests_go.tls_config.TLS_CHROME_110_LATEST)
    print(num, response.text[:100])


if __name__ == '__main__':
    start_time = int(time.time())
    ts = []
    for i in range(1000):
        t = Thread(target=main, args=(i,))
        ts.append(t)
    for t in ts:
        t.start()
