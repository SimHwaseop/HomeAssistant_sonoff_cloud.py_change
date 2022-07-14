import requests,time
from datetime import datetime
from bs4 import BeautifulSoup
from selenium import webdriver

print(datetime.now())

def sonoff_APP():
    url = 'https://raw.githubusercontent.com/CoolKit-Technologies/ha-addon-backEnd/main/src/config/app.ts'
    response = requests.get(url)
    html = BeautifulSoup(response.text, "lxml")
    p = str(html.find('p').get_text())
    p = p.replace("import { debugMode } from './config';", '')
    p = p.replace("// prod", '')
    p = p.replace("let appId = ", '')
    p = p.replace("let appSecret = ", '')
    p = p.replace("if (debugMode) {", '')
    p = p.replace("    appId = ", '')
    p = p.replace("    appSecret = ", '')
    p = p.replace("}", '')
    p = p.replace("export { appId, appSecret ;", '')
    p = p.replace("\n", '')
    p = p.replace("'", '')
    p = p.split(';')
    del p[(len(p)-1)]
    return p

#sonoff_APP()
'''
f = open('cloud.txt','r')
cloud_py = str(f.read())
cloud_py = cloud_py.replace("\n", '\\n')
cloud_py = cloud_py.replace('"', '\\"')
cloud_py = cloud_py.replace("'", '\\\'')
print(cloud_py)
'''

c =('\"\"\"\nhttps://coolkit-technologies.github.io/eWeLink-API/#/en/PlatformOverview\n\"\"\"\nimport asyncio\nimport base64\nimport hashlib\nimport hmac\nimport json\nimport logging\nimport time\nfrom typing import List\n\nfrom aiohttp import ClientConnectorError, WSMessage, ClientWebSocketResponse\n\nfrom .base import XRegistryBase, XDevice, SIGNAL_CONNECTED, SIGNAL_UPDATE\n\n_LOGGER = logging.getLogger(__name__)\n\nRETRY_DELAYS = [15, 60, 5 * 60, 15 * 60, 60 * 60]\n\n# https://coolkit-technologies.github.io/eWeLink-API/#/en/APICenterV2?id=interface-domain-name\nAPI = {\n    \"cn\": \"https://cn-apia.coolkit.cn\",\n    \"as\": \"https://as-apia.coolkit.cc\",\n    \"us\": \"https://us-apia.coolkit.cc\",\n    \"eu\": \"https://eu-apia.coolkit.cc\",\n}\n# https://coolkit-technologies.github.io/eWeLink-API/#/en/APICenterV2?id=http-dispatchservice-app\nWS = {\n    \"cn\": \"https://cn-dispa.coolkit.cn/dispatch/app\",\n    \"as\": \"https://as-dispa.coolkit.cc/dispatch/app\",\n    \"us\": \"https://us-dispa.coolkit.cc/dispatch/app\",\n    \"eu\": \"https://eu-dispa.coolkit.cc/dispatch/app\",\n}\n\nDATA_ERROR = {\n    0: \'online\',\n    503: \'offline\',\n    504: \'timeout\',\n    None: \'unknown\'\n}\n\nAPP = [\n    (\"%s\", \"%s\"),\n    (\"%s\", \"%s\")\n]\n\n\nclass AuthError(Exception):\n    pass\n\n\nclass ResponseWaiter:\n    \"\"\"Class wait right sequences in response messages.\"\"\"\n    _waiters = {}\n\n    def _set_response(self, sequence: str, error: int) -> bool:\n        if sequence not in self._waiters:\n            return False\n        # sometimes the error doesn\'t exists\n        result = DATA_ERROR[error] if error in DATA_ERROR else f\"E#{error}\"\n        self._waiters[sequence].set_result(result)\n        return True\n\n    async def _wait_response(self, sequence: str, timeout: int):\n        self._waiters[sequence] = asyncio.get_event_loop().create_future()\n\n        try:\n            # limit future wait time\n            await asyncio.wait_for(self._waiters[sequence], timeout)\n        except asyncio.TimeoutError:\n            # remove future from waiters, in very rare cases, we can send two\n            # commands with the same sequence\n            self._waiters.pop(sequence, None)\n            return \'timeout\'\n\n        # remove future from waiters and return result\n        return self._waiters.pop(sequence).result()\n\n\nclass XRegistryCloud(ResponseWaiter, XRegistryBase):\n    auth: dict = None\n    devices: dict = None\n    last_ts = 0\n    online = None\n    region = \"eu\"\n\n    task: asyncio.Task = None\n    ws: ClientWebSocketResponse = None\n\n    @property\n    def host(self) -> str:\n        return API[self.region]\n\n    @property\n    def ws_host(self) -> str:\n        return WS[self.region]\n\n    @property\n    def headers(self) -> dict:\n        return {\"Authorization\": \"Bearer \" + self.auth[\"at\"]}\n\n    @property\n    def token(self) -> str:\n        return self.region + \":\" + self.auth[\"at\"]\n\n    async def login(self, username: str, password: str, app=0) -> bool:\n        if username == \"token\":\n            self.region, token = password.split(\":\")\n            return await self.login_token(token, 1)\n\n        # https://coolkit-technologies.github.io/eWeLink-API/#/en/DeveloperGuideV2\n        payload = {}\n        if \"@\" in username:\n            payload[\"email\"] = username\n        elif username.startswith(\"+\"):\n            payload[\"phoneNumber\"] = username\n        else:\n            payload[\"phoneNumber\"] = \"+\" + username\n        payload.update({\n            \"password\": password,\n            \"countryCode\": \"+86\",\n        })\n\n        appid, appsecret = APP[app]\n\n        json_payload = json.dumps(payload, separators=(\',\',\':\')).encode()\n        hex_dig = hmac.new(\n            appsecret.encode(), json_payload, hashlib.sha256\n        ).digest()\n\n        headers = {\n            \"Authorization\": \"Sign \" + base64.b64encode(hex_dig).decode(),\n            \"X-CK-Appid\": appid,\n        }\n        r = await self.session.post(\n            self.host + \"/v2/user/login\", json=payload, headers=headers,\n            timeout=30\n        )\n        resp = await r.json()\n\n        # wrong default region\n        if resp[\"error\"] == 10004:\n            self.region = resp[\"data\"][\"region\"]\n            r = await self.session.post(\n                self.host + \"/v2/user/login\", json=payload, headers=headers,\n                timeout=30\n            )\n            resp = await r.json()\n\n        if resp[\"error\"] != 0:\n            raise AuthError(resp[\"msg\"])\n\n        self.auth = resp[\"data\"]\n        self.auth[\"appid\"] = appid\n\n        return True\n\n    async def login_token(self, token: str, app: int = 0) -> bool:\n        appid = APP[app][0]\n        headers = {\"Authorization\": \"Bearer \" + token, \"X-CK-Appid\": appid}\n        r = await self.session.get(\n            self.host + \"/v2/user/profile\", headers=headers, timeout=30\n        )\n        resp = await r.json()\n        if resp[\"error\"] != 0:\n            raise AuthError(resp[\"msg\"])\n\n        self.auth = resp[\"data\"]\n        self.auth[\"at\"] = token\n        self.auth[\"appid\"] = appid\n\n        return True\n\n    async def get_homes(self) -> dict:\n        r = await self.session.get(\n            self.host + \"/v2/family\", headers=self.headers, timeout=30\n        )\n        resp = await r.json()\n        return {i[\"id\"]: i[\"name\"] for i in resp[\"data\"][\"familyList\"]}\n\n    async def get_devices(self, homes: list = None) -> List[dict]:\n        devices = []\n        for home in homes or [None]:\n            r = await self.session.get(\n                self.host + \"/v2/device/thing\",\n                headers=self.headers, timeout=30,\n                params={\"num\": 0, \"familyid\": home} if home else {\"num\": 0}\n            )\n            resp = await r.json()\n            if resp[\"error\"] != 0:\n                raise Exception(resp[\"msg\"])\n            # item type: 1 - user device, 2 - shared device, 3 - user group,\n            # 5 - share device (home)\n            devices += [\n                i[\"itemData\"] for i in resp[\"data\"][\"thingList\"]\n                if i[\"itemType\"] != 3  # skip groups\n            ]\n        return devices\n\n    async def send(\n            self, device: XDevice, params: dict = None, sequence: str = None,\n            timeout: int = 5\n    ):\n        \"\"\"With params - send new state to device, without - request device\n        state. With zero timeout - won\'t wait response.\n        \"\"\"\n        log = f\"{device[\'deviceid\']} => Cloud4 | \"\n        if params:\n            log += f\"{params} | \"\n\n        # protect cloud from DDoS (it can break connection)\n        while time.time() - self.last_ts < 0.1:\n            log += \"DDoS | \"\n            await asyncio.sleep(0.1)\n        self.last_ts = time.time()\n\n        if sequence is None:\n            sequence = self.sequence()\n        log += sequence\n\n        # https://coolkit-technologies.github.io/eWeLink-API/#/en/APICenterV2?id=websocket-update-device-status\n        payload = {\n            \"action\": \"update\" if params else \"query\",\n            # we need to use device apikey bacause device may be shared from\n            # another account\n            \"apikey\": device[\"apikey\"],\n            \"selfApikey\": self.auth[\"user\"][\"apikey\"],\n            \"deviceid\": device[\'deviceid\'],\n            \"params\": params or [],\n            \"userAgent\": \"app\",\n            \"sequence\": sequence,\n        }\n\n        _LOGGER.debug(log)\n        try:\n            await self.ws.send_json(payload)\n\n            if timeout:\n                # wait for response with same sequence\n                return await self._wait_response(sequence, timeout)\n        except ConnectionResetError:\n            return \'offline\'\n        except Exception as e:\n            _LOGGER.error(log, exc_info=e)\n            return \'E#???\'\n\n    def start(self):\n        self.task = asyncio.create_task(self.run_forever())\n\n    async def stop(self):\n        if self.task:\n            self.task.cancel()\n\n        self.set_online(False)\n\n    def set_online(self, value: bool):\n        _LOGGER.debug(f\"CLOUD {self.online} => {value}\")\n        if self.online == value:\n            return\n        self.online = value\n        self.dispatcher_send(SIGNAL_CONNECTED)\n\n    async def run_forever(self):\n        fails = 0\n\n        while not self.session.closed:\n            if not await self.connect():\n                self.set_online(False)\n\n                delay = RETRY_DELAYS[fails]\n                _LOGGER.debug(f\"Cloud connection retrying in {delay} seconds\")\n                if fails + 1 < len(RETRY_DELAYS):\n                    fails += 1\n                await asyncio.sleep(delay)\n                continue\n\n            fails = 0\n\n            self.set_online(True)\n\n            try:\n                msg: WSMessage\n                async for msg in self.ws:\n                    resp = json.loads(msg.data)\n                    await self._process_ws_msg(resp)\n            except Exception as e:\n                _LOGGER.warning(\"Cloud processing error\", exc_info=e)\n\n    async def connect(self) -> bool:\n        try:\n            # https://coolkit-technologies.github.io/eWeLink-API/#/en/APICenterV2?id=http-dispatchservice-app\n            r = await self.session.get(self.ws_host, headers=self.headers)\n            resp = await r.json()\n\n            # we can use IP, but using domain because security\n            self.ws = await self.session.ws_connect(\n                f\"wss://{resp[\'domain\']}:{resp[\'port\']}/api/ws\", heartbeat=90\n            )\n\n            # https://coolkit-technologies.github.io/eWeLink-API/#/en/APICenterV2?id=websocket-handshake\n            ts = time.time()\n            payload = {\n                \"action\": \"userOnline\",\n                \"at\": self.auth[\"at\"],\n                \"apikey\": self.auth[\"user\"][\"apikey\"],\n                \"appid\": self.auth[\"appid\"],\n                \"nonce\": str(int(ts / 100)),\n                \"ts\": int(ts),\n                \"userAgent\": \"app\",\n                \"sequence\": str(int(ts * 1000)),\n                \"version\": 8,\n            }\n            await self.ws.send_json(payload)\n\n            resp = await self.ws.receive_json()\n            if resp[\"error\"] != 0:\n                raise Exception(resp)\n\n            return True\n\n        except ClientConnectorError as e:\n            _LOGGER.warning(f\"Cloud WS Connection error: {e}\")\n\n        except Exception as e:\n            _LOGGER.error(f\"Cloud WS exception\", exc_info=e)\n\n        return False\n\n    async def _process_ws_msg(self, data: dict):\n        if \"action\" not in data:\n            # response on our command\n            self._set_response(data[\"sequence\"], data[\"error\"])\n\n            # with params response on query, without - on update\n            if \"params\" in data:\n                self.dispatcher_send(SIGNAL_UPDATE, data)\n            elif \"config\" in data:\n                data[\"params\"] = data.pop(\"config\")\n                self.dispatcher_send(SIGNAL_UPDATE, data)\n            elif data[\"error\"] != 0:\n                _LOGGER.warning(f\"Cloud ERROR: {data}\")\n\n        elif data[\"action\"] == \"update\":\n            # new state from device\n            self.dispatcher_send(SIGNAL_UPDATE, data)\n\n        elif data[\"action\"] == \"sysmsg\":\n            # changed device online status\n            self.dispatcher_send(SIGNAL_UPDATE, data)\n\n        elif data[\"action\"] == \"reportSubDevice\":\n            # nothing useful: https://github.com/AlexxIT/SonoffLAN/issues/767\n            pass\n\n        else:\n            _LOGGER.warning(f\"UNKNOWN cloud msg: {data}\")' % (sonoff_APP()[0], sonoff_APP()[1], sonoff_APP()[2], sonoff_APP()[3]))
f = open('/usr/share/hassio/homeassistant/custom_components/sonoff/core/ewelink/cloud.py','w')
f.write(c)
f.close

'''
webdriver_options = webdriver.ChromeOptions()
#webdriver_options.add_argument('headless')
#webdriver_options.add_argument('windows-size=1920x1080')
#webdriver_options.add_argument('disable-gpu')
driver = webdriver.Chrome()#("/usr/lib/chromium-browser/chromedriver", options =  webdriver_options )

url = 'http://localhost.8123/config/system'
driver.get(url)
time.sleep(2)
driver.find_element("xpath", '/html/body/div[1]/ha-authorize//ha-auth-flow//form/ha-formfield/ha-checkbox//div/input').click()
time.sleep(1000)
driver.find_element("xpath", '/html/body/div/ha-authorize//ha-auth-flow//form/ha-form//div/ha-form-string[1]//ha-textfield//label/input').send_keys('restart')
time.sleep(1)
driver.find_element("xpath", '/html/body/div[1]/ha-authorize//ha-auth-flow//form/ha-form//div/ha-form-string[2]//ha-textfield//label/input').send_keys('restart')
time.sleep(1)
driver.find_element("xpath", '//*[@id="button"]').click()
time.sleep(1)
driver.find_element("xpath", '//*[@id="button"]').click()
time.sleep(1)
#driver.find_element("xpath", '//*[@id="button"]').click()
time.sleep(1)
print(datetime.now())
#브라우저 종료
driver.quit()
'''





