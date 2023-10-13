import { useState } from 'react';
import reactLogo from './assets/react.svg';
import viteLogo from '/vite.svg';
import './App.css';

function EncodeBase64URL(data: Uint8Array): string {
    let output = '';
    for (let i = 0; i < data.length; i++)
        output += String.fromCharCode(data[i]);

    return btoa(output.replace(/\+/g, '-').replace(/\//g, '_')).replace(
        /=+$/,
        '',
    );
}

function FormatArrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
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
        'raw',
        keyPair.publicKey,
    );

    // PEM形式に変換
    let publicKeyPEMContents = btoa(btos(exportedPublicKey));
    let publicKeyPEM = '-----BEGIN PUBLIC KEY-----\n';
    while (publicKeyPEMContents.length > 0) {
        publicKeyPEM += publicKeyPEMContents.substring(0, 64) + '\n';
        publicKeyPEMContents = publicKeyPEMContents.substring(64);
    }
    publicKeyPEM += '-----END PUBLIC KEY-----\n';

    // 公開鍵をJWKとしてエクスポート;
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

    // 共有鍵(sharedKey)を使用して暗号化
    const data = await crypto.subtle.encrypt(
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
        publicKeyPEM,
    };

    return ret as { [key: string]: string };
}

function AppEnctyption(message: string) {
    const remotePublicKeyPem: string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENI1qJibR0PlaOqcR1AdB7+rcppom
pnA1jyNEZCFsm0Fz/p54w0ipTwYUW4UtCt7b69a0jzirWEcuRkjjK1kTSg==
-----END PUBLIC KEY-----`;
    EncryptEllipticPCurve(message, remotePublicKeyPem)
        .then((result) => {
            // 結果を取得して処理
            console.log(result);
            alert(JSON.stringify(result));
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
            <div>
                <a href="https://vitejs.dev" target="_blank">
                    <img src={viteLogo} className="logo" alt="Vite logo" />
                </a>
                <a href="https://react.dev" target="_blank">
                    <img
                        src={reactLogo}
                        className="logo react"
                        alt="React logo"
                    />
                </a>
            </div>
            <h1>Vite + React</h1>
            <div className="card">
                <p>
                    秘密情報：
                    <input
                        value={message}
                        onChange={(event) => setMessage(event.target.value)}
                    />
                </p>
                <p>
                    <button onClick={() => AppEnctyption(message)}>
                        暗号化
                    </button>
                </p>
                <p>
                    Edit <code>src/App.tsx</code> and save to test HMR
                </p>
            </div>
            <p className="read-the-docs">
                Click on the Vite and React logos to learn more
            </p>
        </>
    );
}

export default App;
