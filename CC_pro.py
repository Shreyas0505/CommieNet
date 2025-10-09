from resource_client import ResourceClient

PASSPHRASE = "CommieNet"
SALT = b"Syn"

client = ResourceClient("10.107.16.60", passphrase=PASSPHRASE, salt=SALT)
client.connect()
client.upload_file("demo.py", "/tmp/demo.py")

res = client.execute_remote("python3 /tmp/demo.py")

print(res)
client.disconnect()




