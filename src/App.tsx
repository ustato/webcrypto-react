import { useState } from 'react';
import reactLogo from './assets/react.svg';
import viteLogo from '/vite.svg';
import './App.css';

function EncodeBase64URL(data: Uint8Array): string {
    let output = '';
    for (let i = 0; i < data.length; i++)
        output += String.fromCharCode(data[i]);

    return btoa(output.replace(/\+/g, '-').replace(/\//g, '_'));
}

function stob(s: string): Uint8Array {
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

function ConvertPublicKeyPemToJwk(publicKeyPem: string): Uint8Array {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    if (publicKeyPem.startsWith('"')) publicKeyPem = publicKeyPem.slice(1);
    if (publicKeyPem.endsWith('"')) publicKeyPem = publicKeyPem.slice(0, -1);
    publicKeyPem = publicKeyPem.split('\\n').join('');
    publicKeyPem = publicKeyPem.split('\n').join('');
    const pemContents = publicKeyPem.substring(
        pemHeader.length,
        publicKeyPem.length - pemFooter.length,
    );
    const der = stob(atob(pemContents));

    return der;
}

async function EncryptEllipticPCurve(
    message: string,
    remotePublicKeyPem: string,
): Promise<{ [key: string]: string }> {
    // console.log(`Start encrypt message: ${message}`);
    // console.log(`public key: ${remotePublicKeyPem}`);

    const encoder = new TextEncoder();
    const input = encoder.encode(message);

    let keyPair: CryptoKeyPair;
    let iv = crypto.getRandomValues(new Uint8Array(12));
    let ret: { [key: string]: string } | undefined;

    // 鍵ペアを生成
    keyPair = await window.crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256',
        },
        false,
        ['deriveKey', 'deriveBits'],
    );

    // 公開鍵をエクスポート
    const exportedPublicKey = await window.crypto.subtle.exportKey(
        'jwk',
        keyPair.publicKey,
    );

    // 外部の公開鍵をインポート
    const importedPublicKey = await window.crypto.subtle.importKey(
        'spki',
        ConvertPublicKeyPemToJwk(remotePublicKeyPem),
        {
            name: 'ECDH',
            namedCurve: 'P-256',
        },
        false,
        [],
    );

    // 共有鍵を計算
    const sharedKey = await window.crypto.subtle.deriveKey(
        {
            name: 'ECDH',
            public: importedPublicKey,
        },
        keyPair.privateKey,
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt'],
    );

    // 共有鍵(sharedKey)を使用して暗号化
    const data = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            length: 256,
            tagLength: 128,
        },
        sharedKey,
        input,
    );

    // 結果を返す
    ret = {
        iv: EncodeBase64URL(new Uint8Array(iv)),
        enctyptedData: EncodeBase64URL(new Uint8Array(data)),
        jwk: JSON.stringify(exportedPublicKey),
    };

    return ret as { [key: string]: string };
}

function AppEnctyption(message: string, remotePublicKeyPem: string) {
    EncryptEllipticPCurve(message, remotePublicKeyPem)
        .then((result) => {
            // 結果を取得して処理
            console.log(result);
            alert('Encrypted!\n' + JSON.stringify(result));
        })
        .catch(() => {
            // 結果を取得して処理
            alert('失敗しました');
        });
}

function App() {
    const [publicKey, setPublicKey] = useState('');
    const [message, setMessage] = useState('');

    return (
        <>
            <div className="card">
                <ol>
                    <li>`make keys` を実行する</li>
                    <li>
                        クリップボードを貼り付ける：
                        <input
                            value={publicKey}
                            onChange={(event) =>
                                setPublicKey(event.target.value)
                            }
                        />
                    </li>
                    <li>
                        秘密情報を入力する：
                        <input
                            value={message}
                            onChange={(event) => setMessage(event.target.value)}
                        />
                    </li>
                    <li>
                        <button
                            onClick={() => AppEnctyption(message, publicKey)}
                        >
                            暗号化
                        </button>
                    </li>
                    <li>
                        復号
                        <ol>
                            <li>
                                開発者コンソールの jwk を browser_public_key.jwk
                                に保存
                            </li>
                            <li>`make jwk2pem` を実行する</li>
                            <li>
                                python utils/decrypt.py "enctyptedData" "iv"
                                を実行
                            </li>
                        </ol>
                    </li>
                </ol>
            </div>
        </>
    );
}

export default App;
