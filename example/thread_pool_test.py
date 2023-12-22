import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests_go


def main(num):
    response = requests_go.get(url="https://www.baidu.com", tls_config=requests_go.tls_config.TLS_CHROME_110_LATEST)
    print(num, response.text)


if __name__ == '__main__':
    start_time = int(time.time())
    tasklist = []
    thread_pool = ThreadPoolExecutor(max_workers=1000)
    for i in range(1000):
        task = thread_pool.submit(main, i)
        tasklist.append(task)
    for mission in as_completed(tasklist):
        pass
    print("1000个线程耗时为：", time.time() - start_time)
