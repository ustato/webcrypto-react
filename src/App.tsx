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

function btos(b: ArrayBuffer) {
    return String.fromCharCode(...new Uint8Array(b));
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

async function ConvertPublicKeyJwkToPem(key: CryptoKey): Promise<string> {
    const der = await crypto.subtle.exportKey('spki', key);
    let pemContents = btoa(btos(der));
    let pem = '-----BEGIN PUBLIC KEY-----\n';
    while (pemContents.length > 0) {
        pem += pemContents.substring(0, 64) + '\n';
        pemContents = pemContents.substring(64);
    }
    pem += '-----END PUBLIC KEY-----\n';

    return pem;
}

async function GenerateEllipticCurveP256Keys(
    remotePublicKeyPem: string,
): Promise<{
    sharedKey: CryptoKey;
    exportedPublicKey: CryptoKey;
}> {
    // 鍵ペアを生成
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256',
        },
        false,
        ['deriveKey', 'deriveBits'],
    );

    // 外部の公開鍵をインポート
    const importedPublicKey = await crypto.subtle.importKey(
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
    const sharedKey = await crypto.subtle.deriveKey(
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

    return {
        sharedKey,
        exportedPublicKey: keyPair.publicKey,
    };
}

async function EncryptAesGcm256(
    message: string,
    remotePublicKeyPem: string,
): Promise<{
    enctyptedData: string;
    iv: string;
    pem: string;
}> {
    const encoder = new TextEncoder();
    const input = encoder.encode(message);

    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 共通鍵と公開鍵を生成
    const keys = await GenerateEllipticCurveP256Keys(remotePublicKeyPem);

    // 共有鍵を使用して暗号化
    const data = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            length: 256,
            tagLength: 128,
        },
        keys.sharedKey,
        input,
    );

    // 公開鍵をエクスポート
    const exportedPublicKey = await ConvertPublicKeyJwkToPem(
        keys.exportedPublicKey,
    );

    return {
        enctyptedData: EncodeBase64URL(new Uint8Array(data)),
        iv: EncodeBase64URL(new Uint8Array(iv)),
        pem: exportedPublicKey,
    };
}

function AppEnctyption(message: string, remotePublicKeyPem: string) {
    EncryptAesGcm256(message, remotePublicKeyPem)
        .then((result) => {
            console.log(result);
            alert('Encrypted!\n' + JSON.stringify(result));
        })
        .catch((err) => {
            alert(err);
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
                                開発者コンソールの pem を browser_public_key.pem
                                に保存
                            </li>
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
