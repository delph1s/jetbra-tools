import json
import asyncio
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator, Tuple, List, Dict, Any

# 过期时间
NOW_DATETIME = datetime.now()
EXPIRE_DATE = (NOW_DATETIME + timedelta(days=365 * 3)).strftime("%Y-%m-%d")
BASE_DIR = Path(__file__).parent.resolve()


async def search(name: str = None, show_code: bool = False) -> Generator[Tuple[str, str, str, str], None, None]:
    """
    搜索JetBrains插件市场中的插件信息。

    Args:
        name (str, optional): 要搜索的插件名称. Defaults to None.
        show_code (bool, optional): 是否获取插件代码. Defaults to False.

    Yields:
        Generator[Tuple[str, str, str, str], None, None]: 返回包含插件信息的元组:
            - 如果show_code为True: (插件ID, 插件名称, 定价模式, 插件代码)
            - 如果show_code为False: (插件ID, 插件名称)

    Raises:
        httpx.RequestError: 当API请求失败时
    """
    types = ["FREEMIUM", "PAID"]
    params = {
        "offset": 0,
        "max": 10000,
        "pricingModels": types,
    }
    if name:
        params["search"] = name

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://plugins.jetbrains.com/api/searchPlugins",
            params=params,
            timeout=30.0,
        )
        response.raise_for_status()
        plugins = response.json().get("plugins", [])

    if show_code:
        for plugin in plugins:
            code = await get_plugin_code(plugin["id"])
            yield str(plugin["id"]), plugin["name"], plugin["pricingModel"], code
    else:
        for plugin in plugins:
            yield str(plugin["id"]), plugin["name"]


async def get_plugin_code(plugin_id: str) -> str:
    """
    获取指定插件的产品代码。

    Args:
        plugin_id (str): 插件的唯一标识符

    Returns:
        str: 插件的产品代码，如果不存在则返回None

    Raises:
        httpx.RequestError: 当API请求失败时
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://plugins.jetbrains.com/api/plugins/{plugin_id}", timeout=30.0)
        response.raise_for_status()
        plugin_info = response.json()
        if plugin_info.get("purchaseInfo"):
            return plugin_info["purchaseInfo"].get("productCode")


async def get_plugin_codes(
    plugin_ids: List[str],
) -> Generator[Tuple[str, str], None, None]:
    """
    批量获取多个插件的产品代码。

    Args:
        plugin_ids (List[str]): 插件ID列表

    Yields:
        Generator[Tuple[str, str], None, None]: 生成(插件ID, 产品代码)的元组

    Raises:
        httpx.RequestError: 当API请求失败时
    """
    async with httpx.AsyncClient() as client:
        tasks = [
            client.get(f"https://plugins.jetbrains.com/api/plugins/{plugin_id}", timeout=30.0)
            for plugin_id in plugin_ids
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    for response in responses:
        if isinstance(response, httpx.Response) and response.status_code == 200:
            rsp_json = response.json()
            if rsp_json.get("purchaseInfo"):
                yield str(rsp_json["id"]), rsp_json["purchaseInfo"].get("productCode")


class JetBrainPlugin:
    """JetBrains插件管理类，用于处理插件信息的获取和许可证生成。"""

    def __init__(self):
        """初始化插件管理器，加载现有的插件数据。"""
        plugins_json_file = BASE_DIR / "plugins.json"
        if plugins_json_file.is_file():
            with open(plugins_json_file, "r") as f:
                self.id_map = json.load(f)
        else:
            self.id_map = dict()

    async def update(self) -> "JetBrainPlugin":
        """
        更新插件信息，获取新的插件数据。

        Returns:
            JetBrainPlugin: 返回自身实例

        Raises:
            httpx.RequestError: 当API请求失败时
        """
        remote_id_map = {i[0]: i[1] async for i in search()}
        keys = remote_id_map.keys() - self.id_map.keys()
        async for plugin_id, plugin_code in get_plugin_codes(keys):
            self.id_map[plugin_id] = {
                "name": remote_id_map[plugin_id],
                "code": plugin_code,
                "extended": True,
            }
        self.dump()
        return self

    def make_licenses(self) -> "JetBrainPlugin":
        """
        生成许可证文件。

        Returns:
            JetBrainPlugin: 返回自身实例
        """
        with open(BASE_DIR / "licenses_ide.json", "r") as f:
            license_data = json.load(f)

        products_json = [
            {
                "code": product["code"],
                "fallbackDate": EXPIRE_DATE,
                "paidUpTo": EXPIRE_DATE,
                "extended": product["extended"],
            }
            for product in self.id_map.values()
        ]

        for ide in license_data["products"]:
            ide["fallbackDate"] = EXPIRE_DATE
            ide["paidUpTo"] = EXPIRE_DATE

        license_data["products"].extend(products_json)

        with open(BASE_DIR / "licenses.json", "w") as f:
            json.dump(license_data, f, indent=2)

        return self

    def dump(self) -> None:
        """将插件信息保存到文件。"""
        with open(BASE_DIR / "plugins.json", "w") as f:
            json.dump(self.id_map, f, indent=2, sort_keys=True)


async def main() -> None:
    """主函数，执行插件更新和许可证生成流程。"""
    obj = JetBrainPlugin()
    await obj.update()
    obj.make_licenses()


def run() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    run()
