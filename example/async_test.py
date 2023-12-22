import asyncio

import requests_go


async def session_main():
    session = requests_go.async_session()
    response = await session.get(url="https://www.baidu.com", tls_config=requests_go.tls_config.TLS_CHROME_110_LATEST)
    print("session_main:", response.text)


async def api_main():
    response = await requests_go.async_get(url="https://www.baidu.com", tls_config=requests_go.tls_config.TLS_CHROME_110_LATEST)
    print("api_main:", response.text)


async def run():
    await asyncio.gather(session_main(), api_main())


if __name__ == '__main__':
    asyncio.run(run())
