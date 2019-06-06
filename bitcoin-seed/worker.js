importScripts("crypto.js");

function BytesToWordArray(bytes)
{
    return new CryptoJS.lib.WordArray.init(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), bytes.length);
}

function WordArrayToBytes(...wordArrays)
{
    let totalCount = 0;
    wordArrays.forEach(e => totalCount += e.sigBytes);

    const ret = new Uint8Array(totalCount);
    let totalIndex = 0;

    for (let i = 0; i < wordArrays.length; ++i)
    {
        const currentWordArray = wordArrays[i];
        const words = currentWordArray.words;
        const count = currentWordArray.sigBytes;

        let index = 0;
        let offset = 0;

        for (let j = 0; j < count; ++j)
        {
            ret[totalIndex++] = words[index] >> ((3 - offset) << 3) & 0xff;

            if (++offset === 4)
            {
                offset = 0;
                ++index;
            }
        }
    }

    return ret;
}

function PBKDF2(password, salt, iterations = 2048, dklen = 512/32)
{
    return WordArrayToBytes(CryptoJS.PBKDF2(
        typeof password === "string" ? password : BytesToWordArray(password),
        typeof salt === "string" ? salt : BytesToWordArray(salt),
        { iterations: iterations, keySize: dklen, hasher: CryptoJS.algo.SHA512 }));
}

const ecc_p =  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const ecc_a =  0n;
const ecc_b =  7n;
const ecc_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const ecc_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const ecc_n =  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

function modinv(a, n)
{
    let lm = 1n;
    let hm = 0n;
    let low = a % n;
    let high = n;
    let ratio;
    let nm;
    let nnew;

    while (low < 0n)
        low += n;

    while (low > 1n)
    {
        ratio = high / low;
        nm = hm - lm * ratio;
        nnew = high - low * ratio;
        hm = lm;
        high = low;
        lm = nm;
        low = nnew;
    }

    return lm % n;
}

function ecAdd(ax, ay, bx, by)
{
    const lambda = ((by - ay) * (modinv(bx - ax, ecc_p))) % ecc_p;
    const x = (lambda * lambda - ax - bx) % ecc_p;
    const y = (lambda * (ax - x) - ay) % ecc_p;
    
    return [x, y];
}

function ecDouble(ax, ay)
{
    const lambda = ((3n * ax * ax + ecc_a) * (modinv(2n * ay, ecc_p))) % ecc_p;
    const x = (lambda * lambda - 2n * ax) % ecc_p;
    const y = (lambda * (ax - x) - ay) % ecc_p;
    
    return [x, y];
}

function bigintToBoolArray(bigint)
{
    if (bigint < 0n)
        return [false];
    
    const values = [];
    while (bigint > 0n)
    {
        values.push(Boolean(bigint & 0x1n));
        bigint >>= 1n;
    }
    return values.reverse();
}

function EccMultiply(gx, gy, scalar)
{
    let qx = gx;
    let qy = gy;
    
    const bits = bigintToBoolArray(scalar);
    for (let i = 1; i < bits.length; ++i)
    {
        const ret = ecDouble(qx, qy);
        qx = ret[0];
        qy = ret[1];
        if (bits[i])
        {
            const ret2 = ecAdd(qx, qy, gx, gy);
            qx = ret2[0];
            qy = ret2[1];
        }
    }
    
    while (qy < 0n)
        qy += ecc_p;
    
    return [qx, qy];
}

function bigintToByteArray(bigint)
{
    const ret = [];
    
    while (bigint > 0n)
    {
        ret.push(Number(bigint & 0xffn));
        bigint >>= 8n;
    }
    
    return ret;
}

function byteArrayToBigint(bytes)
{
    let bigint = 0n;
    for (let i = 0; i < bytes.length; ++i)
    {
        bigint <<= 8n;
        bigint |= BigInt(bytes[i]);
    }
    
    return bigint;
}

function bigintToByteArray_littleEndian(bytes)
{
    return bigintToByteArray(bytes).reverse();
}

function getECCKeypair(val)
{
    if (val == 0n || val >= ecc_n)
    {
        throw "invalid private key value";
    }
    
    return EccMultiply(ecc_Gx, ecc_Gy, val);
}

onmessage = ev =>
{
    const type = ev.data._type;
    const data = ev.data._data;
    let result;
    switch (type)
    {
        case "PBKDF2":
            result = PBKDF2(data[0], data[1], 2048, 512/32);
            break;
        case "ecpoint":
            result = getECCKeypair(data);
            break;
    }
    postMessage(result);
};
