
function SHA256(msg, options)
{
    const result = CryptoJS.SHA256(typeof msg === "string" ? msg : BytesToWordArray(msg));
    if (options && !options.asBytes)
        return result.toString(CryptoJS.enc.Hex);

    return WordArrayToBytes(result);
}

function RIPEMD160(msg, options)
{
    const result = CryptoJS.RIPEMD160(typeof msg === "string" ? msg : BytesToWordArray(msg));
    if (options && !options.asBytes)
        return result.toString(CryptoJS.enc.Hex);

    return WordArrayToBytes(result);
}

function HmacSHA512(msg, key)
{
    return WordArrayToBytes(CryptoJS.HmacSHA512(
        typeof msg === "string" ? msg : BytesToWordArray(msg),
        typeof key === "string" ? key : BytesToWordArray(key)
    ));
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

function BytesToWordArray(bytes)
{
    return new CryptoJS.lib.WordArray.init(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), bytes.length);
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
    const array = bigintToByteArray(bytes);
    while (array.length < 32)
        array.push(0);

    return array.reverse();
}

const base58Characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const base58CharsIndices = 
{
    '1': 0, '2': 1, '3': 2, '4': 3,
    '5': 4, '6': 5, '7': 6, '8': 7,
    '9': 8, 'A': 9, 'B': 10, 'C': 11,
    'D': 12, 'E': 13, 'F': 14, 'G': 15,
    'H': 16, 'J': 17, 'K': 18, 'L': 19,
    'M': 20, 'N': 21, 'P': 22, 'Q': 23,
    'R': 24, 'S': 25, 'T': 26, 'U': 27,
    'V': 28, 'W': 29, 'X': 30, 'Y': 31,
    'Z': 32, 'a': 33, 'b': 34, 'c': 35,
    'd': 36, 'e': 37, 'f': 38, 'g': 39,
    'h': 40, 'i': 41, 'j': 42, 'k': 43,
    'm': 44, 'n': 45, 'o': 46, 'p': 47,
    'q': 48, 'r': 49, 's': 50, 't': 51,
    'u': 52, 'v': 53, 'w': 54, 'x': 55,
    'y': 56, 'z': 57,
}

/**
 * 
 * @param {Number[]} bytes 
 */
function base58encode(bytes)
{
    let leading_zeroes = 0;
    while (bytes[leading_zeroes] == 0)
        ++leading_zeroes;

    bytes.push.apply(bytes, SHA256(SHA256(bytes)).slice(0, 4));
    
    let bigint = 0n;
    for (let i = 0; i < bytes.length; ++i)
    {
        bigint <<= 8n;
        bigint |= BigInt(bytes[i]);
    }
    
    let ret = "";
    while (bigint > 0n)
    {
        const remainder = bigint % 58n;
        bigint = bigint / 58n;
        ret += base58Characters[Number(remainder)];
    }
    
    for (let i = 0; i < leading_zeroes; ++i)
        ret += base58Characters[0];

    return ret.split("").reverse().join("");
}

function base58decode(text)
{
    let newstring = text.split("").reverse().join("");
    for (let i = 0; i < text.length; ++i)
    {
        if (text[i] == base58Characters[0])
            newstring = newstring.substr(0, newstring.length - 1);
        else
            break;
    }

    let bigint = 0n;
    for (let i = newstring.length - 1; i >= 0; --i)
        bigint = bigint * 58n + BigInt(base58CharsIndices[newstring[i]]);
    
    let bytes = bigintToByteArray(bigint);
    if (bytes[bytes.length - 1] == 0)
        bytes.pop();
    
    bytes.reverse();
    
    const checksum = bytes.slice(bytes.length - 4, bytes.length);
    bytes.splice(bytes.length - 4, 4);
    const sha_result = SHA256(SHA256(bytes, { asBytes: true }), { asBytes: true });
    
    for (var i = 0; i < 4; ++i)
    {
        if (sha_result[i] != checksum[i])
            throw new Error("invalid checksum");
    }

    return bytes;
}

function getECCKeypair(val)
{
    if (val == 0n || val >= ecc_n)
    {
        throw "invalid private key value";
    }
    
    return EccMultiply(ecc_Gx, ecc_Gy, val);
}

async function getECCKeypair_worker(val)
{
    if (val == 0n || val >= ecc_n)
    {
        throw "invalid private key value";
    }
    
    return await new Promise(resolve => EnqueueWorkerTask({ _type: "ecpoint", _data: val }, resolve));
}

function makeAddress(keypair)
{
    const key_bytes = [];
    
    const bytes_public_x = bigintToByteArray(keypair[0]);
    while (bytes_public_x.length < 32)
        bytes_public_x.push(0);
    
    key_bytes.push.apply(key_bytes, bytes_public_x);
    
    key_bytes.push(0x02 + Number(keypair[1] & 0x1n));
            
    key_bytes.reverse();
    const sha_result_1 = SHA256(key_bytes, { asBytes: true });
    const ripemd_result_2 = RIPEMD160(sha_result_1, { asBytes: true });
    const ripemd_extended = [0];
    ripemd_extended.push.apply(ripemd_extended, ripemd_result_2);
        
    return base58encode(ripemd_extended);
}

function makeUncompressedAddress(keypair)
{
    const key_bytes = [];
    
    const bytes_public_x = bigintToByteArray(keypair[0]);
    const bytes_public_y = bigintToByteArray(keypair[1]);
    while (bytes_public_x.length < 32)
        bytes_public_x.push(0);
        
    while (bytes_public_y.length < 32)
        bytes_public_y.push(0);
    
    key_bytes.push.apply(key_bytes, bytes_public_y);
    key_bytes.push.apply(key_bytes, bytes_public_x);
    key_bytes.push(0x04);
    
    key_bytes.reverse();
    const sha_result_1 = SHA256(key_bytes, { asBytes: true });
    const ripemd_result_2 = RIPEMD160(sha_result_1, { asBytes: true });
    const ripemd_extended = [0];
    ripemd_extended.push.apply(ripemd_extended, ripemd_result_2);
        
    return base58encode(ripemd_extended);
}

function makeSegwitAddress(keypair)
{
    const key_bytes = [];
    
    const bytes_public_x = bigintToByteArray(keypair[0]);
    while (bytes_public_x.length < 32)
        bytes_public_x.push(0);
    
    key_bytes.push.apply(key_bytes, bytes_public_x);
    
    key_bytes.push(0x02 + Number(keypair[1] & 0x1n));
    
    key_bytes.reverse();
    const sha_result_1 = SHA256(key_bytes, { asBytes: true });
    const keyhash = RIPEMD160(sha_result_1, { asBytes: true });
    
    const redeemscript = [0x00, 0x14];
    redeemscript.push.apply(redeemscript, keyhash);
    
    const redeemscripthash = [0x05];
    redeemscripthash.push.apply(redeemscripthash, RIPEMD160(SHA256(redeemscript, { asBytes: true }), { asBytes: true }));
    
    return base58encode(redeemscripthash);
}

const bech32Chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32HrpExpand(hrp)
{
    const ret = [];
    for (let i = 0; i < hrp.length; ++i)
        ret.push(hrp.charCodeAt(i) >> 5);

    ret.push(0);

    for (let i = 0; i < hrp.length; ++i)
        ret.push(hrp.charCodeAt(i) & 0x1f);

    return ret;
}

function bech32Polymod(values)
{
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;

    for (let i = 0; i < values.length; ++i)
    {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];

        for (let j = 0; j < 5; ++j)
        {
            if ((b >> j) & 1)
                chk ^= GEN[j];
        }
    }

    return chk;
}

function bech32CreateChecksum(hrp, data)
{
    const asd = bech32HrpExpand(hrp);
    asd.push.apply(asd, data);
    asd.push.apply(asd, [0, 0, 0, 0, 0, 0]);

    const polymod = bech32Polymod(asd) ^ 1;

    ret = [];
    for (let i = 0; i < 6; ++i)
        ret.push((polymod >> 5 * (5 - i)) & 31);

    return ret;
}

function makeBech32Address(keypair)
{
    const key_bytes = [];
    
    const bytes_public_x = bigintToByteArray(keypair[0]);
    while (bytes_public_x.length < 32)
        bytes_public_x.push(0);
    
    key_bytes.push.apply(key_bytes, bytes_public_x);
    
    key_bytes.push(0x02 + Number(keypair[1] & 0x1n));
    
    key_bytes.reverse();
    const sha_result_1 = SHA256(key_bytes, { asBytes: true });
    const keyhash = RIPEMD160(sha_result_1, { asBytes: true });
    
    const redeemscript = [0x00, 0x14];
    redeemscript.push.apply(redeemscript, keyhash);
    
    let value = 0;
    let bits = 0;

    const result = [0];
    for (let i = 0; i < 20; ++i)
    {
        value = ((value << 8) | keyhash[i]) & 0xFFFFFF;
        bits += 8;

        while (bits >= 5)
        {
            bits -= 5;
            result.push((value >> bits) & 0x1F);
        }
    }
    
    let address = "bc1";
    for (let i = 0; i < result.length; ++i)
        address += bech32Chars[result[i]];

    const checksum = bech32CreateChecksum("bc", result);
    for (let i = 0; i < checksum.length; ++i)
        address += bech32Chars[checksum[i]];

    return address;
}

function makePrivateKey(bigint, compressed = true)
{
    const privkey = [];
    if (compressed)
        privkey.push(0x01);
    
    const temp = bigintToByteArray(bigint);
    while (temp.length < 32)
        temp.push(0);
    
    privkey.push.apply(privkey, temp);
    privkey.push(0x80);
    privkey.reverse();
    return base58encode(privkey);
}

function Uint32ToBytes(num)
{
    return [num >>> 24, (num >>> 16) & 0xff, (num >>> 8) & 0xff, num & 0xff];
}

function BytesToUint32(bytes)
{
    return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
}

function SerializeECCKeypairCompressed(keypair)
{
    return [0x2 + Number(keypair[1] & 1n), ...bigintToByteArray_littleEndian(keypair[0])];
}

function ModPow(num, exponent, mod)
{
    let ret = 1n;

    while (exponent !== 0n)
    {
        if ((exponent & 1n) !== 0n)
            ret = (ret * num) % mod;

        exponent >>= 1n;
        num = (num * num) % mod;
    }

    return ret;
}

// extendedPrivKey: [privkey: Uint8Array, chainCode: Uint8Array]
// extendedPubKey: [pubkey: ecpoint, chainCode: Uint8Array]

/**
 * 
 * (parent: extendedPrivKey, index: uint32) -> extendedPrivKey
 */
async function CKD_Priv(parent, index)
{
    const isHardened = (index & 0x80000000) !== 0;
    const parentKey = parent[0];
    const parentKeyBigint = byteArrayToBigint(parentKey);
    const parentChainCode = parent[1];

    let I;
    if (isHardened)
        I = HmacSHA512([0x00, ...parentKey, ...Uint32ToBytes(index)], parentChainCode);
    else
        I = HmacSHA512([...SerializeECCKeypairCompressed(await getECCKeypair_worker(parentKeyBigint)), ...Uint32ToBytes(index)], parentChainCode);
    
    const IL = I.slice(0, 32);
    const IR = I.slice(32, 64);

    const parsed256IL = byteArrayToBigint(IL);
    const childKey = (parsed256IL + parentKeyBigint) % ecc_n;

    // In case parse256(IL) >= n or ki == 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2^127.)
    if (parsed256IL >= ecc_n || childKey === 0n)
        return await CKD_Priv(extendedKey, index + 1, isHardened);

    return [childKey, IR];
}

/**
 * 
 * (parent: extendedPubKey, index: uint32) -> extendedPubKey
 */
async function CKD_Pub(parent, index)
{
    const isHardened = (index & 0x80000000) !== 0;
    const parentKeyPair = parent[0];
    const pointX = byteArrayToBigint(parentKeyPair[0]);
    const isOdd = parentKeyPair[1] === 3;

    const val = pointX ** 3n + 7n;
    let pointY = ModPow(val, (ecc_p + 1n) >> 2n, ecc_p);
    if (pointY < 0n)
        pointY += ecc_p;

    if (((pointY & 1n) === 1n) !== isOdd)
        pointY = ecc_p - pointY;

    const parentKeyPairBigint = [pointX, pointY];
    const parentChainCode = parent[1];

    if (isHardened)
        throw new Error("Cannot derive hardened child key of extended public key");

    const I = HmacSHA512([...SerializeECCKeypairCompressed(parentKeyPairBigint), ...Uint32ToBytes(index)], parentChainCode);
    
    const IL = I.slice(0, 32);
    const IR = I.slice(32, 64);

    const tempBigint = byteArrayToBigint(IL);
    const multiplied = await getECCKeypair_worker(tempBigint);
    const childKeyPair = ecAdd(multiplied[0], multiplied[1], parentKeyPairBigint[0], parentKeyPairBigint[1]);
    if (childKeyPair[1] < 0n)
        childKeyPair[1] += ecc_p;

    // In case parse256(IL) >= n or Ki is the point at infinity, the resulting key is invalid, and one should proceed with the next value for i.
    if (tempBigint >= ecc_n || tempBigint === 0n)
        return await CKD_Pub(parent, index + 1);

    return [childKeyPair, IR];
}

/**
 * 
 * (parent: extendedPrivKey) -> extendedPubKey
 */
async function CKD_N(parent)
{
    return [await getECCKeypair_worker(byteArrayToBigint(parent[0])), parent[1]];
}

function Hash160(data)
{
    return RIPEMD160(SHA256(data));
}

function GetExtendedKeyFingerprint(key)
{
    return Hash160(key).slice(0, 4);
}

function HexStringToByteArray(hexString)
{
    const ret = [];
    for (let i = 0; i < hexString.length; i += 2)
        ret.push(Number.parseInt(hexString.substr(i, 2), 16));

    return ret;
}

function GetMasterKeyFromSeed(seed)
{
    const I = HmacSHA512(seed, "Bitcoin seed");

    const IL = I.slice(0, 32);
    const IR = I.slice(32, 64);

    return [byteArrayToBigint(IL), IR];
}

/**
 * 
 * @param {Boolean} isPrivate 
 * @param {Number} depth 
 * @param {Number[]} parentKeyFingerprint 
 * @param {Number} childIndex 
 * @param {Number[]} chainCode 
 * @param {Number[]} keyData 
 * @param {String} type 
 */
function SerializeExtendedKey(isPrivate, depth, parentKeyFingerprint, childIndex, chainCode, keyData, type)
{
    let versionBytes;
    switch (type)
    {
        case "49":
            // ypub yprv
            if (isPrivate)
                versionBytes = [0x04, 0x9D, 0x78, 0x78];
            else
                versionBytes = [0x04, 0x9D, 0x7C, 0xB2];
            break;
        case "84":
            if (isPrivate)
                versionBytes = [0x04, 0xB2, 0x43, 0x0C];
            else
                versionBytes = [0x04, 0xB2, 0x47, 0x46];
            break;
        case "44":
        default:
            if (isPrivate)
                versionBytes = [0x04, 0x88, 0xAD, 0xE4];
            else
                versionBytes = [0x04, 0x88, 0xB2, 0x1E];
            break;
    }

    if (depth > 255)
        throw new Error("Depth must be 255 at most");

    const finalResult = [...versionBytes, depth, ...parentKeyFingerprint, ...Uint32ToBytes(childIndex), ...chainCode, ...keyData];
    return base58encode(finalResult);
}

/**
 * 
 * @param {String} extendedKey 
 */
function UnextendKey(extendedKey)
{
    const decodedKey = base58decode(extendedKey);
    const keyData = decodedKey.slice(45);
    const key = byteArrayToBigint(keyData.slice(1));

    if (keyData[0] === 0)
        return makePrivateKey(key);
    else
    {
        const keypair = [key, BigInt(keyData[0])];
        switch (extendedKey[0])
        {
            case "x":
                return makeAddress(keypair);
            case "y":
                return makeSegwitAddress(keypair);
            case "z":
                return makeBech32Address(keypair);
            default:
                throw new Error("Unknown key type");
        }
    }
}

async function DeriveKey(extendedKey, path, toPrivate, type = "44")
{
    if (path[0] !== "m")
        throw new Error("Path must start with \"m\"");

    path = path.substr(2).split("/");
    const childIndices = [];

    for (let index of path)
    {
        if (index === "")
            continue;

        const match = index.match(/(\d+)(')?/);
        if (match)
        {
            const index = Number.parseInt(match[1]);
            const isHardened = match[2] !== undefined;
            childIndices.push((isHardened ? (index | 0x80000000) : index) >>> 0);
        }
        else
            throw new Error("invalid path");
    }
    
    const decodedKey = base58decode(extendedKey);

    let currentDepth = decodedKey[4];
    let chainCode = decodedKey.slice(13, 45);
    let keyData = decodedKey.slice(45);
    const fromPrivate = keyData[0] === 0;
    if (!fromPrivate && toPrivate)
        throw new Error("Cannot derive private key from public key");

    let parentKeyData;

    let lastIndex = BytesToUint32(decodedKey.slice(9, 13));
    for (let childIndex of childIndices)
    {
        parentKeyData = keyData;
        lastIndex = childIndex;
        let derivedKey;
        if (fromPrivate)
        {
            const privkey = keyData.slice(1);
            //if (toPrivate)
            //{
            derivedKey = await CKD_Priv([privkey, chainCode], childIndex);
            keyData = [0x00, ...bigintToByteArray_littleEndian(derivedKey[0])];
            //}
            //else
            //{
            //    derivedKey = CKD_N([privkey, chainCode]);
            //    keyData = SerializeECCKeypairCompressed(derivedKey[0]);
            //}
        }
        else
        {
            derivedKey = await CKD_Pub([[keyData.slice(1), keyData[0]], chainCode], childIndex);
            keyData = SerializeECCKeypairCompressed(derivedKey[0]);
        }

        chainCode = derivedKey[1];
        ++currentDepth;
    }

    let fingerprint;
    const convertToPublic = !toPrivate && keyData[0] === 0;
    const convertParentToPublic = !toPrivate && parentKeyData && parentKeyData[0] === 0;
    if (convertToPublic)
        keyData = SerializeECCKeypairCompressed(await getECCKeypair_worker(byteArrayToBigint(keyData.slice(1))));

    if (convertParentToPublic)
        parentKeyData = SerializeECCKeypairCompressed(await getECCKeypair_worker(byteArrayToBigint(parentKeyData.slice(1))));

    if (parentKeyData)
    {
        if (toPrivate)
        {
            const pubkey = SerializeECCKeypairCompressed(await getECCKeypair_worker(byteArrayToBigint(parentKeyData.slice(1))));
            fingerprint = GetExtendedKeyFingerprint(pubkey);
        }
        else
            fingerprint = GetExtendedKeyFingerprint(parentKeyData);
    }
    else
        fingerprint = decodedKey.slice(5, 9);

    return SerializeExtendedKey(toPrivate, currentDepth, fingerprint, lastIndex, chainCode, keyData, type);
}

function test()
{
    /*
    const seed = HexStringToByteArray("000102030405060708090a0b0c0d0e0f");
    const masterKey = GetMasterKeyFromSeed(seed);
    const masterPrivKey = [0, ...bigintToByteArray_littleEndian(masterKey[0])];
    const masterPubKey = SerializeECCKeypairCompressed(getECCKeypair(masterKey[0]));
    const masterChainCode = masterKey[1];
    const xprv = SerializeExtendedKey(true, 0, [0, 0, 0, 0], 0, masterChainCode, masterPrivKey, "44");
    const xpub = SerializeExtendedKey(false, 0, [0, 0, 0, 0], 0, masterChainCode, masterPubKey, "44");
    console.log(xprv);
    console.log("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    
    console.log(xpub);
    console.log("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");*/
}

test();
