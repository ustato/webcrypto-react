import click
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@click.command()
@click.argument("enctypted_data", type=click.STRING)
@click.argument("iv", type=click.STRING)
@click.option(
    "--local_private_key",
    required=True,
    type=click.Path(),
    default="prime256v1_private_key.pem",
)
@click.option(
    "--remote_public_key",
    required=True,
    type=click.Path(),
    default="browser_public_key.pem",
)
def decrypt(
    enctypted_data,
    iv,
    local_private_key,
    remote_public_key,
):
    # 自分の公開鍵をPEM形式から読み込む
    with open(local_private_key, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 相手からの公開鍵をPEM形式から読み込む
    with open(remote_public_key, "rb") as f:
        opponent_public_key = serialization.load_pem_public_key(f.read())

    # ECDH鍵交換を実行
    shared_key = private_key.exchange(ec.ECDH(), opponent_public_key)

    # 共有鍵からAES-GCM 256ビットキーを生成
    key = shared_key[0:32]  # 共有鍵を32バイト（256ビット）に切り詰め

    nonce = base64.b64decode(iv.encode())
    data = base64.b64decode(enctypted_data.encode())

    tag_length = 16
    tag = data[-tag_length:]

    # 暗号文部分を取得（認証タグを除く）
    ciphertext = data[:-tag_length]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag=tag))
    decryptor = cipher.decryptor()

    plaintext = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    print("復号結果:", plaintext)


if __name__ == "__main__":
    decrypt()
