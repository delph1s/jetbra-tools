import base64
import os
import random
import sys
import time
from base64 import b64encode
from pathlib import Path

import uvicorn
from crypto_plus import CryptoPlus
from fastapi import Response, FastAPI
from starlette.responses import PlainTextResponse

from jetbra_key import extract_key_str, gen_certificate, gen_license, gen_sign, gen_power_cfg, JETBRAINS_ROOT_CA_MOD, JETBRAINS_SERVER_ROOT_CA_MOD
from jetbra_plugins import run as jetbra_plugins_run


BASE_DIR = Path(__file__).parent.resolve()
SERVER_UID = os.environ.get('SERVER_UID', 'delph1s')

KEY_PATH = BASE_DIR / "ca.key"
CERT_PATH = BASE_DIR / "ca.crt"
SERVER_KEY_PATH = BASE_DIR / "ls_ca.key"
SERVER_CERT_PATH = BASE_DIR / "ls_ca.crt"
LICENSES_INFO_PATH = BASE_DIR / "licenses.json"

server_subject_name = f'{SERVER_UID}.lsrv.jetbrains.com'
server_uid_camel = SERVER_UID.upper()[:1] + SERVER_UID[1:]

if not KEY_PATH.is_file() or not CERT_PATH.is_file():
    with (
        open(KEY_PATH, "wb") as f_key,
        open(CERT_PATH, "wb") as f_cert,
    ):
        new_private_bytes, new_public_bytes = gen_certificate()
        f_key.write(new_private_bytes)
        f_cert.write(new_public_bytes)
else:
    # new_key = CryptoPlus.load(key_path=KEY_PATH)
    # new_cert = CryptoPlus.load(key_path=CERT_PATH)
    # if f'CN={server_subject_name}' != new_cert.key.subject.rfc4514_string():
    #     new_key.dump_cert(subject_name=server_subject_name, issuer_name='License Servers CA', cert_path=CERT_PATH)
    with (
        open(KEY_PATH, "rb") as f_key,
        open(CERT_PATH, "rb") as f_cert,
    ):
        new_private_bytes = f_key.read()
        new_public_bytes = f_cert.read()

if not SERVER_KEY_PATH.is_file() or not SERVER_CERT_PATH.is_file():
    with (
        open(SERVER_KEY_PATH, "wb") as f_key,
        open(SERVER_CERT_PATH, "wb") as f_cert,
    ):
        new_server_private_bytes, new_server_public_bytes = gen_certificate(subject_name=server_subject_name, issuer_name="License Servers CA")
        f_key.write(new_server_private_bytes)
        f_cert.write(new_server_public_bytes)
else:
    # new_server_key = CryptoPlus.load(key_path=KEY_PATH)
    # new_server_cert = CryptoPlus.load(key_path=CERT_PATH)
    # if f'CN={server_subject_name}' != new_server_cert.key.subject.rfc4514_string():
    #     new_server_key.dump_cert(subject_name=server_subject_name, issuer_name='License Servers CA', cert_path=SERVER_CERT_PATH)
    with (
        open(SERVER_KEY_PATH, "rb") as f_key,
        open(SERVER_CERT_PATH, "rb") as f_cert,
    ):
        new_server_private_bytes = f_key.read()
        new_server_public_bytes = f_cert.read()

# 首次启动更新插件信息
# jetbra_plugins_run()

with (
    open(LICENSES_INFO_PATH, "r") as f_licenses,
):
    new_licenses_data = f_licenses.read()

# new_sign = gen_sign(new_public_bytes)
# new_power_cfg = gen_power_cfg(new_sign[0], new_sign[1], jb_root_ca_sign=JETBRAINS_ROOT_CA_MOD)
# new_server_sign = gen_sign(new_server_public_bytes)
# new_server_power_cfg = gen_power_cfg(new_server_sign[0], new_server_sign[1], jb_root_ca_sign=JETBRAINS_SERVER_ROOT_CA_MOD)
# new_power_patch = (
#     "; license server\n"
#     f"{new_power_cfg}\n"
#     "; client\n"
#     f"{new_server_sign}"
# )
rsa1 = CryptoPlus.loads(new_server_private_bytes)
rsa2 = CryptoPlus.loads(new_private_bytes)

cert1 = extract_key_str(new_server_public_bytes)
arg1 = int.from_bytes(CryptoPlus.loads(cert1).key.signature, 'big')
mod1 = JETBRAINS_SERVER_ROOT_CA_MOD

cert2 = extract_key_str(new_public_bytes)
arg2 = int.from_bytes(CryptoPlus.loads(cert2).key.signature, 'big')
mod2 = JETBRAINS_ROOT_CA_MOD

patch = f'; Activation Code\nEQUAL,{arg2},65537,{mod2}->{pow(arg2, 65537, rsa2.public_key.n)}\n; License Server\nEQUAL,{arg1},65537,{mod1}->{pow(arg1, 65537, rsa1.public_key.n)}'



class XMLResponse(Response):
    media_type = 'application/xml'


app = FastAPI()


@app.get('/rpc/ping.action')
async def ping(salt, machineId):
    confirmation_stamp = f'{int(1000 * time.time())}:{machineId}'
    server_lease = f'4102415999000:{SERVER_UID}'
    xml_content = f'''<PingResponse><action>NONE</action><confirmationStamp>{confirmation_stamp}:SHA1withRSA:{b64encode(rsa1.sign(confirmation_stamp.encode(), 'SHA1')).decode()}:{cert1}</confirmationStamp><leaseSignature>SHA512withRSA-{b64encode(rsa2.sign(server_lease.encode(), 'SHA512')).decode()}-{cert2}</leaseSignature><message></message><responseCode>OK</responseCode><salt>{salt}</salt><serverLease>{server_lease}</serverLease><serverUid>{SERVER_UID}</serverUid><validationDeadlinePeriod>-1</validationDeadlinePeriod><validationPeriod>600000</validationPeriod></PingResponse>'''
    xml = f'''<!-- SHA1withRSA-{base64.b64encode(rsa1.sign(xml_content.encode(), 'SHA1')).decode()}-{cert1} -->\n{xml_content}'''
    return XMLResponse(xml)


@app.get('/rpc/obtainTicket.action')
async def obtain_ticket(salt, machineId, userName):
    confirmation_stamp = f'{int(1000 * time.time())}:{machineId}'
    server_lease = f'4102415999000:{SERVER_UID}'
    xml_content = f'''<ObtainTicketResponse><action>NONE</action><confirmationStamp>{confirmation_stamp}:SHA1withRSA:{b64encode(rsa1.sign(confirmation_stamp.encode(), 'SHA1')).decode()}:{cert1}</confirmationStamp><leaseSignature>SHA512withRSA-{b64encode(rsa2.sign(server_lease.encode(), 'SHA512')).decode()}-{cert2}</leaseSignature><message></message><prolongationPeriod>600000</prolongationPeriod><responseCode>OK</responseCode><salt>{salt}</salt><serverLease>{server_lease}</serverLease><serverUid>{SERVER_UID}</serverUid><ticketId>{random.randbytes(5).hex()}</ticketId><ticketProperties>licensee={userName}\tlicenseType=4\tmetadata=0120211231PSAN000005</ticketProperties><validationDeadlinePeriod>-1</validationDeadlinePeriod><validationPeriod>600000</validationPeriod></ObtainTicketResponse>'''
    xml = f'''<!-- SHA1withRSA-{base64.b64encode(rsa1.sign(xml_content.encode(), 'SHA1')).decode()}-{cert1} -->\n{xml_content}'''
    return XMLResponse(xml)


@app.get('/rpc/releaseTicket.action')
async def release_ticket(salt="", machineId=""):
    confirmation_stamp = f'{int(1000 * time.time())}:{machineId}'
    server_lease = f'4102415999000:{SERVER_UID}'
    xml_content = f'''<ReleaseTicketRpcService><action>NONE</action><confirmationStamp>{confirmation_stamp}:SHA1withRSA:{b64encode(rsa1.sign(confirmation_stamp.encode(), 'SHA1')).decode()}:{cert1}</confirmationStamp><leaseSignature>SHA512withRSA-{b64encode(rsa2.sign(server_lease.encode(), 'SHA512')).decode()}-{cert2}</leaseSignature><message></message><responseCode>OK</responseCode><salt>{salt}</salt><serverLease>{server_lease}</serverLease><serverUid>{SERVER_UID}</serverUid><validationDeadlinePeriod>-1</validationDeadlinePeriod><validationPeriod>600000</validationPeriod></ReleaseTicketRpcService>'''
    xml = f'''<!-- SHA1withRSA-{base64.b64encode(rsa1.sign(xml_content.encode(), 'SHA1')).decode()}-{cert1} -->\n{xml_content}'''
    print(xml)
    return XMLResponse(xml)


@app.get('/')
async def power():
    return PlainTextResponse(patch)


@app.get('/code')
async def code(license_id=None, license_name=None, assignee_name=None, assignee_email=None):
    return PlainTextResponse(gen_license(new_public_bytes, new_private_bytes, new_licenses_data, license_id, license_name, assignee_name, assignee_email))


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8001)
