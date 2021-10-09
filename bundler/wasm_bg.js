import * as wasm from './wasm_bg.wasm';

const lTextDecoder = typeof TextDecoder === 'undefined' ? (0, module.require)('util').TextDecoder : TextDecoder;

let cachedTextDecoder = new lTextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

const heap = new Array(32).fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

let WASM_VECTOR_LEN = 0;

const lTextEncoder = typeof TextEncoder === 'undefined' ? (0, module.require)('util').TextEncoder : TextEncoder;

let cachedTextEncoder = new lTextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

const u32CvtShim = new Uint32Array(2);

const uint64CvtShim = new BigUint64Array(u32CvtShim.buffer);

let stack_pointer = 32;

function addBorrowedObject(obj) {
    if (stack_pointer == 1) throw new Error('out of js stack');
    heap[--stack_pointer] = obj;
    return stack_pointer;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}
/**
* Returns the git commit hash and commit date of the commit this library was built against.
* @returns {string}
*/
export function build_id() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.build_id(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Generates random Base64 encoded asset type as a Base64 string. Used in asset definitions.
* @see {@link
* module:Findora-Wasm~TransactionBuilder#add_operation_create_asset|add_operation_create_asset}
* for instructions on how to define an asset with a new
* asset type
* @returns {string}
*/
export function random_asset_type() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.random_asset_type(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Generates asset type as a Base64 string from a JSON-serialized JavaScript value.
* @param {any} val
* @returns {string}
*/
export function asset_type_from_jsvalue(val) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.asset_type_from_jsvalue(retptr, addBorrowedObject(val));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Given a serialized state commitment and transaction, returns true if the transaction correctly
* hashes up to the state commitment and false otherwise.
* @param {string} state_commitment - String representing the state commitment.
* @param {string} authenticated_txn - String representing the transaction.
* @see {@link module:Network~Network#getTxn|Network.getTxn} for instructions on fetching a transaction from the ledger.
* @see {@link module:Network~Network#getStateCommitment|Network.getStateCommitment}
* for instructions on fetching a ledger state commitment.
* @throws Will throw an error if the state commitment or the transaction fails to deserialize.
* @param {string} state_commitment
* @param {string} authenticated_txn
* @returns {boolean}
*/
export function verify_authenticated_txn(state_commitment, authenticated_txn) {
    var ptr0 = passStringToWasm0(state_commitment, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = passStringToWasm0(authenticated_txn, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    var ret = wasm.verify_authenticated_txn(ptr0, len0, ptr1, len1);
    return ret !== 0;
}

/**
* ...
* @returns {XfrPublicKey}
*/
export function get_null_pk() {
    var ret = wasm.get_null_pk();
    return XfrPublicKey.__wrap(ret);
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

let cachegetUint32Memory0 = null;
function getUint32Memory0() {
    if (cachegetUint32Memory0 === null || cachegetUint32Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint32Memory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory0;
}

function getArrayJsValueFromWasm0(ptr, len) {
    const mem = getUint32Memory0();
    const slice = mem.subarray(ptr / 4, ptr / 4 + len);
    const result = [];
    for (let i = 0; i < slice.length; i++) {
        result.push(takeObject(slice[i]));
    }
    return result;
}
/**
* Build transfer from account balance to utxo tx.
* @param {XfrPublicKey} recipient - UTXO Asset receiver.
* @param {u64} amount - Transfer amount.
* @param {string} sk - Ethereum wallet private key.
* @param {u64} nonce - Transaction nonce for sender.
* @param {XfrPublicKey} recipient
* @param {BigInt} amount
* @param {string} sk
* @param {BigInt} nonce
* @returns {string}
*/
export function transfer_to_utxo_from_account(recipient, amount, sk, nonce) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(recipient, XfrPublicKey);
        var ptr0 = recipient.ptr;
        recipient.ptr = 0;
        uint64CvtShim[0] = amount;
        const low1 = u32CvtShim[0];
        const high1 = u32CvtShim[1];
        var ptr2 = passStringToWasm0(sk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        uint64CvtShim[0] = nonce;
        const low3 = u32CvtShim[0];
        const high3 = u32CvtShim[1];
        wasm.transfer_to_utxo_from_account(retptr, ptr0, low1, high1, ptr2, len2, low3, high3);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Recover ecdsa private key from mnemonic.
* @param {string} phrase
* @param {string} password
* @returns {string}
*/
export function recover_sk_from_mnemonic(phrase, password) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        wasm.recover_sk_from_mnemonic(retptr, ptr0, len0, ptr1, len1);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Recover ethereum address from ecdsa private key, eg. 0x73c71...
* @param {string} sk
* @returns {string}
*/
export function recover_address_from_sk(sk) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passStringToWasm0(sk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.recover_address_from_sk(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Serialize ethereum address used to abci query nonce.
* @param {string} address
* @returns {string}
*/
export function get_serialized_address(address) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passStringToWasm0(address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.get_serialized_address(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Returns a JavaScript object containing decrypted owner record information,
* where `amount` is the decrypted asset amount, and `asset_type` is the decrypted asset type code.
*
* @param {ClientAssetRecord} record - Owner record.
* @param {OwnerMemo} owner_memo - Owner memo of the associated record.
* @param {XfrKeyPair} keypair - Keypair of asset owner.
* @see {@link module:Findora-Wasm~ClientAssetRecord#from_json_record|ClientAssetRecord.from_json_record} for information about how to construct an asset record object
* from a JSON result returned from the ledger server.
* @param {ClientAssetRecord} record
* @param {OwnerMemo | undefined} owner_memo
* @param {XfrKeyPair} keypair
* @returns {any}
*/
export function open_client_asset_record(record, owner_memo, keypair) {
    _assertClass(record, ClientAssetRecord);
    let ptr0 = 0;
    if (!isLikeNone(owner_memo)) {
        _assertClass(owner_memo, OwnerMemo);
        ptr0 = owner_memo.ptr;
        owner_memo.ptr = 0;
    }
    _assertClass(keypair, XfrKeyPair);
    var ret = wasm.open_client_asset_record(record.ptr, ptr0, keypair.ptr);
    return takeObject(ret);
}

/**
* Extracts the public key as a string from a transfer key pair.
* @param {XfrKeyPair} key_pair
* @returns {string}
*/
export function get_pub_key_str(key_pair) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(key_pair, XfrKeyPair);
        wasm.get_pub_key_str(retptr, key_pair.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Extracts the private key as a string from a transfer key pair.
* @param {XfrKeyPair} key_pair
* @returns {string}
*/
export function get_priv_key_str(key_pair) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(key_pair, XfrKeyPair);
        wasm.get_priv_key_str(retptr, key_pair.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Creates a new transfer key pair.
* @returns {XfrKeyPair}
*/
export function new_keypair() {
    var ret = wasm.new_keypair();
    return XfrKeyPair.__wrap(ret);
}

/**
* Generates a new keypair deterministically from a seed string and an optional name.
* @param {string} seed_str
* @param {string | undefined} name
* @returns {XfrKeyPair}
*/
export function new_keypair_from_seed(seed_str, name) {
    var ptr0 = passStringToWasm0(seed_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(name) ? 0 : passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    var ret = wasm.new_keypair_from_seed(ptr0, len0, ptr1, len1);
    return XfrKeyPair.__wrap(ret);
}

/**
* Returns base64 encoded representation of an XfrPublicKey.
* @param {XfrPublicKey} key
* @returns {string}
*/
export function public_key_to_base64(key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(key, XfrPublicKey);
        wasm.public_key_to_base64(retptr, key.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Converts a base64 encoded public key string to a public key.
* @param {string} pk
* @returns {XfrPublicKey}
*/
export function public_key_from_base64(pk) {
    var ptr0 = passStringToWasm0(pk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.public_key_from_base64(ptr0, len0);
    return XfrPublicKey.__wrap(ret);
}

/**
* Expresses a transfer key pair as a hex-encoded string.
* To decode the string, use `keypair_from_str` function.
* @param {XfrKeyPair} key_pair
* @returns {string}
*/
export function keypair_to_str(key_pair) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(key_pair, XfrKeyPair);
        wasm.keypair_to_str(retptr, key_pair.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Constructs a transfer key pair from a hex-encoded string.
* The encode a key pair, use `keypair_to_str` function.
* @param {string} str
* @returns {XfrKeyPair}
*/
export function keypair_from_str(str) {
    var ptr0 = passStringToWasm0(str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.keypair_from_str(ptr0, len0);
    return XfrKeyPair.__wrap(ret);
}

/**
* Generates a new credential issuer key.
* @param {JsValue} attributes - Array of attribute types of the form `[{name: "credit_score",
* size: 3}]`. The size refers to byte-size of the credential. In this case, the "credit_score"
* attribute is represented as a 3 byte string "760". `attributes` is the list of attribute types
* that the issuer can sign off on.
* @param {any} attributes
* @returns {CredentialIssuerKeyPair}
*/
export function wasm_credential_issuer_key_gen(attributes) {
    var ret = wasm.wasm_credential_issuer_key_gen(addHeapObject(attributes));
    return CredentialIssuerKeyPair.__wrap(ret);
}

/**
* Verifies a credential commitment. Used to confirm that a credential is tied to a ledger
* address.
* @param {CredIssuerPublicKey} issuer_pub_key - The credential issuer that has attested to the
* credentials that have been committed to.
* @param {CredentialCommitment} Credential commitment
* @param {CredPoK} Proof of knowledge of the underlying commitment
* @param {XfrPublicKey} Ledger address linked to this credential commitment.
* @throws Will throw an error during verification failure (i.e. the supplied ledger address is
* incorrect, the commitment is tied to a different credential issuer, or the proof of knowledge is
* invalid, etc.)
* @param {CredIssuerPublicKey} issuer_pub_key
* @param {CredentialCommitment} commitment
* @param {CredentialPoK} pok
* @param {XfrPublicKey} xfr_pk
*/
export function wasm_credential_verify_commitment(issuer_pub_key, commitment, pok, xfr_pk) {
    _assertClass(issuer_pub_key, CredIssuerPublicKey);
    _assertClass(commitment, CredentialCommitment);
    _assertClass(pok, CredentialPoK);
    _assertClass(xfr_pk, XfrPublicKey);
    wasm.wasm_credential_verify_commitment(issuer_pub_key.ptr, commitment.ptr, pok.ptr, xfr_pk.ptr);
}

/**
* Generates a new reveal proof from a credential commitment key.
* @param {CredUserSecretKey} user_secret_key - Secret key of the credential user who owns
* the credentials.
* @param {Credential} credential - Credential whose attributes will be revealed.
* @param {JsValue} reveal_fields - Array of strings representing attribute fields to reveal.
* @throws Will throw an error if a reveal proof cannot be generated from the credential
* or ```reveal_fields``` fails to deserialize.
* @param {CredUserSecretKey} user_secret_key
* @param {Credential} credential
* @param {CredentialCommitmentKey} key
* @param {any} reveal_fields
* @returns {CredentialPoK}
*/
export function wasm_credential_open_commitment(user_secret_key, credential, key, reveal_fields) {
    _assertClass(user_secret_key, CredUserSecretKey);
    _assertClass(credential, Credential);
    _assertClass(key, CredentialCommitmentKey);
    var ret = wasm.wasm_credential_open_commitment(user_secret_key.ptr, credential.ptr, key.ptr, addHeapObject(reveal_fields));
    return CredentialPoK.__wrap(ret);
}

/**
* Generates a new credential user key.
* @param {CredIssuerPublicKey} issuer_pub_key - The credential issuer that can sign off on this
* user's attributes.
* @param {CredIssuerPublicKey} issuer_pub_key
* @returns {CredentialUserKeyPair}
*/
export function wasm_credential_user_key_gen(issuer_pub_key) {
    _assertClass(issuer_pub_key, CredIssuerPublicKey);
    var ret = wasm.wasm_credential_user_key_gen(issuer_pub_key.ptr);
    return CredentialUserKeyPair.__wrap(ret);
}

/**
* Generates a signature on user attributes that can be used to create a credential.
* @param {CredIssuerSecretKey} issuer_secret_key - Secret key of credential issuer.
* @param {CredUserPublicKey} user_public_key - Public key of credential user.
* @param {JsValue} attributes - Array of attribute assignments of the form `[{name: "credit_score",
* val: "760"}]`.
* @throws Will throw an error if the signature cannot be generated.
* @param {CredIssuerSecretKey} issuer_secret_key
* @param {CredUserPublicKey} user_public_key
* @param {any} attributes
* @returns {CredentialSignature}
*/
export function wasm_credential_sign(issuer_secret_key, user_public_key, attributes) {
    _assertClass(issuer_secret_key, CredIssuerSecretKey);
    _assertClass(user_public_key, CredUserPublicKey);
    var ret = wasm.wasm_credential_sign(issuer_secret_key.ptr, user_public_key.ptr, addHeapObject(attributes));
    return CredentialSignature.__wrap(ret);
}

/**
* Generates a signature on user attributes that can be used to create a credential.
* @param {CredIssuerPublicKey} issuer_public_key - Public key of credential issuer.
* @param {CredentialSignature} signature - Credential issuer signature on attributes.
* @param {JsValue} attributes - Array of attribute assignments of the form `[{name: "credit_score",
* val: "760"}]'.
* @param {CredIssuerPublicKey} issuer_public_key
* @param {CredentialSignature} signature
* @param {any} attributes
* @returns {Credential}
*/
export function create_credential(issuer_public_key, signature, attributes) {
    try {
        _assertClass(issuer_public_key, CredIssuerPublicKey);
        _assertClass(signature, CredentialSignature);
        var ret = wasm.create_credential(issuer_public_key.ptr, signature.ptr, addBorrowedObject(attributes));
        return Credential.__wrap(ret);
    } finally {
        heap[stack_pointer++] = undefined;
    }
}

/**
* Generates a credential commitment. A credential commitment can be used to selectively reveal
* attribute assignments.
* @param {CredUserSecretKey} user_secret_key - Secret key of credential user.
* @param {XfrPublicKey} user_public_key - Ledger signing key to link this credential to.
* @param {Credential} credential - Credential object.
* @param {CredUserSecretKey} user_secret_key
* @param {XfrPublicKey} user_public_key
* @param {Credential} credential
* @returns {CredentialCommitmentData}
*/
export function wasm_credential_commit(user_secret_key, user_public_key, credential) {
    _assertClass(user_secret_key, CredUserSecretKey);
    _assertClass(user_public_key, XfrPublicKey);
    _assertClass(credential, Credential);
    var ret = wasm.wasm_credential_commit(user_secret_key.ptr, user_public_key.ptr, credential.ptr);
    return CredentialCommitmentData.__wrap(ret);
}

/**
* Selectively reveals attributes committed to in a credential commitment
* @param {CredUserSecretKey} user_sk - Secret key of credential user.
* @param {Credential} credential - Credential object.
* @param {JsValue} reveal_fields - Array of string names representing credentials to reveal (i.e.
* `["credit_score"]`).
* @param {CredUserSecretKey} user_sk
* @param {Credential} credential
* @param {any} reveal_fields
* @returns {CredentialRevealSig}
*/
export function wasm_credential_reveal(user_sk, credential, reveal_fields) {
    _assertClass(user_sk, CredUserSecretKey);
    _assertClass(credential, Credential);
    var ret = wasm.wasm_credential_reveal(user_sk.ptr, credential.ptr, addHeapObject(reveal_fields));
    return CredentialRevealSig.__wrap(ret);
}

/**
* Verifies revealed attributes from a commitment.
* @param {CredIssuerPublicKey} issuer_pub_key - Public key of credential issuer.
* @param {JsValue} attributes - Array of attribute assignments to check of the form `[{name: "credit_score",
* val: "760"}]`.
* @param {CredentialCommitment} commitment - Commitment to the credential.
* @param {CredentialPoK} pok - Proof that the credential commitment is valid and commits
* to the attribute values being revealed.
* @param {CredIssuerPublicKey} issuer_pub_key
* @param {any} attributes
* @param {CredentialCommitment} commitment
* @param {CredentialPoK} pok
*/
export function wasm_credential_verify(issuer_pub_key, attributes, commitment, pok) {
    _assertClass(issuer_pub_key, CredIssuerPublicKey);
    _assertClass(commitment, CredentialCommitment);
    _assertClass(pok, CredentialPoK);
    wasm.wasm_credential_verify(issuer_pub_key.ptr, addHeapObject(attributes), commitment.ptr, pok.ptr);
}

/**
* Returns information about traceable assets for a given transfer.
* @param {JsValue} xfr_body - JSON of a transfer note from a transfer operation.
* @param {AssetTracerKeyPair} tracer_keypair - Asset tracer keypair.
* @param {JsValue} candidate_assets - List of asset types traced by the tracer keypair.
* @param {any} xfr_body
* @param {AssetTracerKeyPair} tracer_keypair
* @param {any} _candidate_assets
* @returns {any}
*/
export function trace_assets(xfr_body, tracer_keypair, _candidate_assets) {
    _assertClass(tracer_keypair, AssetTracerKeyPair);
    var ret = wasm.trace_assets(addHeapObject(xfr_body), tracer_keypair.ptr, addHeapObject(_candidate_assets));
    return takeObject(ret);
}

/**
* Returns bech32 encoded representation of an XfrPublicKey.
* @param {XfrPublicKey} key
* @returns {string}
*/
export function public_key_to_bech32(key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(key, XfrPublicKey);
        wasm.public_key_to_bech32(retptr, key.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Converts a bech32 encoded public key string to a public key.
* @param {string} addr
* @returns {XfrPublicKey}
*/
export function public_key_from_bech32(addr) {
    var ptr0 = passStringToWasm0(addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.public_key_from_bech32(ptr0, len0);
    return XfrPublicKey.__wrap(ret);
}

/**
* @param {string} pk
* @returns {string}
*/
export function bech32_to_base64(pk) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passStringToWasm0(pk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.bech32_to_base64(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* @param {string} pk
* @returns {string}
*/
export function base64_to_bech32(pk) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passStringToWasm0(pk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.base64_to_bech32(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
* @param {string} key_pair
* @param {string} password
* @returns {Uint8Array}
*/
export function encryption_pbkdf2_aes256gcm(key_pair, password) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passStringToWasm0(key_pair, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        wasm.encryption_pbkdf2_aes256gcm(retptr, ptr0, len0, ptr1, len1);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
* @param {Uint8Array} enc_key_pair
* @param {string} password
* @returns {string}
*/
export function decryption_pbkdf2_aes256gcm(enc_key_pair, password) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passArray8ToWasm0(enc_key_pair, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        wasm.decryption_pbkdf2_aes256gcm(retptr, ptr0, len0, ptr1, len1);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* @param {string} sk_str
* @returns {XfrKeyPair | undefined}
*/
export function create_keypair_from_secret(sk_str) {
    var ptr0 = passStringToWasm0(sk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.create_keypair_from_secret(ptr0, len0);
    return ret === 0 ? undefined : XfrKeyPair.__wrap(ret);
}

/**
* @param {XfrKeyPair} kp
* @returns {XfrPublicKey}
*/
export function get_pk_from_keypair(kp) {
    _assertClass(kp, XfrKeyPair);
    var ret = wasm.get_pk_from_keypair(kp.ptr);
    return XfrPublicKey.__wrap(ret);
}

/**
* Randomly generate a 12words-length mnemonic.
* @returns {string}
*/
export function generate_mnemonic_default() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.generate_mnemonic_default(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Generate mnemonic with custom length and language.
* - @param `wordslen`: acceptable value are one of [ 12, 15, 18, 21, 24 ]
* - @param `lang`: acceptable value are one of [ "en", "zh", "zh_traditional", "fr", "it", "ko", "sp", "jp" ]
* @param {number} wordslen
* @param {string} lang
* @returns {string}
*/
export function generate_mnemonic_custom(wordslen, lang) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passStringToWasm0(lang, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.generate_mnemonic_custom(retptr, wordslen, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Restore the XfrKeyPair from a mnemonic with a default bip44-path,
* that is "m/44'/917'/0'/0/0" ("m/44'/coin'/account'/change/address").
* @param {string} phrase
* @returns {XfrKeyPair}
*/
export function restore_keypair_from_mnemonic_default(phrase) {
    var ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.restore_keypair_from_mnemonic_default(ptr0, len0);
    return XfrKeyPair.__wrap(ret);
}

/**
* Restore the XfrKeyPair from a mnemonic with custom params,
* in bip44 form.
* @param {string} phrase
* @param {string} lang
* @param {BipPath} path
* @returns {XfrKeyPair}
*/
export function restore_keypair_from_mnemonic_bip44(phrase, lang, path) {
    var ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = passStringToWasm0(lang, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    _assertClass(path, BipPath);
    var ret = wasm.restore_keypair_from_mnemonic_bip44(ptr0, len0, ptr1, len1, path.ptr);
    return XfrKeyPair.__wrap(ret);
}

/**
* Restore the XfrKeyPair from a mnemonic with custom params,
* in bip49 form.
* @param {string} phrase
* @param {string} lang
* @param {BipPath} path
* @returns {XfrKeyPair}
*/
export function restore_keypair_from_mnemonic_bip49(phrase, lang, path) {
    var ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = passStringToWasm0(lang, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    _assertClass(path, BipPath);
    var ret = wasm.restore_keypair_from_mnemonic_bip49(ptr0, len0, ptr1, len1, path.ptr);
    return XfrKeyPair.__wrap(ret);
}

/**
* ID of FRA, in `String` format.
* @returns {string}
*/
export function fra_get_asset_code() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.fra_get_asset_code(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Fee smaller than this value will be denied.
* @returns {BigInt}
*/
export function fra_get_minimal_fee() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.fra_get_minimal_fee(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        u32CvtShim[0] = r0;
        u32CvtShim[1] = r1;
        const n0 = uint64CvtShim[0];
        return n0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* The destination for fee to be transfered to.
* @returns {XfrPublicKey}
*/
export function fra_get_dest_pubkey() {
    var ret = wasm.fra_get_dest_pubkey();
    return XfrPublicKey.__wrap(ret);
}

/**
* The system address used to reveive delegation principals.
* @returns {string}
*/
export function get_delegation_target_address() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.get_coinbase_address(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* @returns {string}
*/
export function get_coinbase_address() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.get_coinbase_address(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* @returns {string}
*/
export function get_coinbase_principal_address() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.get_coinbase_address(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* @returns {BigInt}
*/
export function get_delegation_min_amount() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.get_delegation_min_amount(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        u32CvtShim[0] = r0;
        u32CvtShim[1] = r1;
        const n0 = uint64CvtShim[0];
        return n0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @returns {BigInt}
*/
export function get_delegation_max_amount() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.get_delegation_max_amount(retptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        u32CvtShim[0] = r0;
        u32CvtShim[1] = r1;
        const n0 = uint64CvtShim[0];
        return n0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}
/**
* When an asset is defined, several options governing the assets must be
* specified:
* 1. **Traceable**: Records and identities of traceable assets can be decrypted by a provided tracing key. By defaults, assets do not have
* any tracing policies.
* 2. **Transferable**: Non-transferable assets can only be transferred once from the issuer to another user. By default, assets are transferable.
* 3. **Updatable**: Whether the asset memo can be updated. By default, assets are not updatable.
* 4. **Transfer signature rules**: Signature weights and threshold for a valid transfer. By
*    default, there are no special signature requirements.
* 5. **Max units**: Optional limit on the total number of units of this asset that can be issued.
*    By default, assets do not have issuance caps.
* @see {@link module:Findora-Wasm~TracingPolicies|TracingPolicies} for more information about tracing policies.
* @see {@link module:Findora-Wasm~TransactionBuilder#add_operation_update_memo|add_operation_update_memo} for more information about how to add
* a memo update operation to a transaction.
* @see {@link module:Findora-Wasm~SignatureRules|SignatureRules} for more information about co-signatures.
* @see {@link
* module:Findora-Wasm~TransactionBuilder#add_operation_create_asset|add_operation_create_asset}
* for information about how to add asset rules to an asset definition.
*/
export class AssetRules {

    static __wrap(ptr) {
        const obj = Object.create(AssetRules.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_assetrules_free(ptr);
    }
    /**
    * Create a default set of asset rules. See class description for defaults.
    * @returns {AssetRules}
    */
    static new() {
        var ret = wasm.assetrules_new();
        return AssetRules.__wrap(ret);
    }
    /**
    * Adds an asset tracing policy.
    * @param {TracingPolicy} policy - Tracing policy for the new asset.
    * @param {TracingPolicy} policy
    * @returns {AssetRules}
    */
    add_tracing_policy(policy) {
        const ptr = this.__destroy_into_raw();
        _assertClass(policy, TracingPolicy);
        var ret = wasm.assetrules_add_tracing_policy(ptr, policy.ptr);
        return AssetRules.__wrap(ret);
    }
    /**
    * Set a cap on the number of units of this asset that can be issued.
    * @param {BigInt} max_units - Maximum number of units that can be issued.
    * @param {BigInt} max_units
    * @returns {AssetRules}
    */
    set_max_units(max_units) {
        const ptr = this.__destroy_into_raw();
        uint64CvtShim[0] = max_units;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ret = wasm.assetrules_set_max_units(ptr, low0, high0);
        return AssetRules.__wrap(ret);
    }
    /**
    * Transferability toggle. Assets that are not transferable can only be transferred by the asset
    * issuer.
    * @param {boolean} transferable - Boolean indicating whether asset can be transferred.
    * @param {boolean} transferable
    * @returns {AssetRules}
    */
    set_transferable(transferable) {
        const ptr = this.__destroy_into_raw();
        var ret = wasm.assetrules_set_transferable(ptr, transferable);
        return AssetRules.__wrap(ret);
    }
    /**
    * The updatable flag determines whether the asset memo can be updated after issuance.
    * @param {boolean} updatable - Boolean indicating whether asset memo can be updated.
    * @see {@link module:Findora-Wasm~TransactionBuilder#add_operation_update_memo|add_operation_update_memo} for more information about how to add
    * a memo update operation to a transaction.
    * @param {boolean} updatable
    * @returns {AssetRules}
    */
    set_updatable(updatable) {
        const ptr = this.__destroy_into_raw();
        var ret = wasm.assetrules_set_updatable(ptr, updatable);
        return AssetRules.__wrap(ret);
    }
    /**
    * Co-signature rules. Assets with co-signatue rules require additional weighted signatures to
    * be transferred.
    * @param {SignatureRules} multisig_rules - Co-signature restrictions.
    * @param {SignatureRules} multisig_rules
    * @returns {AssetRules}
    */
    set_transfer_multisig_rules(multisig_rules) {
        const ptr = this.__destroy_into_raw();
        _assertClass(multisig_rules, SignatureRules);
        var ptr0 = multisig_rules.ptr;
        multisig_rules.ptr = 0;
        var ret = wasm.assetrules_set_transfer_multisig_rules(ptr, ptr0);
        return AssetRules.__wrap(ret);
    }
    /**
    * Set the decimal number of asset. Return error string if failed, otherwise return changed asset.
    * #param {Number} decimals - The number of decimals used to set its user representation.
    * Decimals should be 0 ~ 255.
    * @param {number} decimals
    * @returns {AssetRules}
    */
    set_decimals(decimals) {
        const ptr = this.__destroy_into_raw();
        var ret = wasm.assetrules_set_decimals(ptr, decimals);
        return AssetRules.__wrap(ret);
    }
}
/**
* Key pair used by asset tracers to decrypt asset amounts, types, and identity
* commitments associated with traceable asset transfers.
* @see {@link module:Findora-Wasm.TracingPolicy|TracingPolicy} for information about tracing policies.
* @see {@link module:Findora-Wasm~AssetRules#add_tracing_policy|add_tracing_policy} for information about how to add a tracing policy to
* an asset definition.
*/
export class AssetTracerKeyPair {

    static __wrap(ptr) {
        const obj = Object.create(AssetTracerKeyPair.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_assettracerkeypair_free(ptr);
    }
    /**
    * Creates a new tracer key pair.
    * @returns {AssetTracerKeyPair}
    */
    static new() {
        var ret = wasm.assettracerkeypair_new();
        return AssetTracerKeyPair.__wrap(ret);
    }
}
/**
* Object representing an asset definition. Used to fetch tracing policies and any other
* information that may be required to construct a valid transfer or issuance.
*/
export class AssetType {

    static __wrap(ptr) {
        const obj = Object.create(AssetType.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_assettype_free(ptr);
    }
    /**
    * Builds an asset type from a JSON-encoded JavaScript value.
    * @param {JsValue} val - JSON-encoded asset type fetched from ledger server with the `asset_token/{code}` route.
    * Note: The first field of an asset type is `properties`. See the example below.
    *
    * @example
    * "properties":{
    *   "code":{
    *     "val":[151,8,106,38,126,101,250,236,134,77,83,180,43,152,47,57,83,30,60,8,132,218,48,52,167,167,190,244,34,45,78,80]
    *   },
    *   "issuer":{"key":“iFW4jY_DQVSGED05kTseBBn0BllPB9Q9escOJUpf4DY=”},
    *   "memo":“test memo”,
    *   "asset_rules":{
    *     "transferable":true,
    *     "updatable":false,
    *     "transfer_multisig_rules":null,
    *     "max_units":5000
    *   }
    * }
    *
    * @see {@link module:Findora-Network~Network#getAssetProperties|Network.getAsset} for information about how to
    * fetch an asset type from the ledger server.
    * @param {any} json
    * @returns {AssetType}
    */
    static from_json(json) {
        try {
            var ret = wasm.assettype_from_json(addBorrowedObject(json));
            return AssetType.__wrap(ret);
        } finally {
            heap[stack_pointer++] = undefined;
        }
    }
    /**
    * Fetch the tracing policies associated with this asset type.
    * @returns {TracingPolicies}
    */
    get_tracing_policies() {
        var ret = wasm.assettype_get_tracing_policies(this.ptr);
        return TracingPolicies.__wrap(ret);
    }
}
/**
* Object representing an authenticable asset record. Clients can validate authentication proofs
* against a ledger state commitment.
*/
export class AuthenticatedAssetRecord {

    static __wrap(ptr) {
        const obj = Object.create(AuthenticatedAssetRecord.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_authenticatedassetrecord_free(ptr);
    }
    /**
    * Given a serialized state commitment, returns true if the
    * authenticated UTXO proofs validate correctly and false otherwise. If the proofs validate, the
    * asset record contained in this structure exists on the ledger and is unspent.
    * @param {string} state_commitment - String representing the state commitment.
    * @see {@link module:Findora-Network~Network#getStateCommitment|getStateCommitment} for instructions on fetching a ledger state commitment.
    * @throws Will throw an error if the state commitment fails to deserialize.
    * @param {string} state_commitment
    * @returns {boolean}
    */
    is_valid(state_commitment) {
        var ptr0 = passStringToWasm0(state_commitment, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.authenticatedassetrecord_is_valid(this.ptr, ptr0, len0);
        return ret !== 0;
    }
    /**
    * Builds an AuthenticatedAssetRecord from a JSON-encoded asset record returned from the ledger
    * server.
    * @param {JsValue} val - JSON-encoded asset record fetched from ledger server.
    * @see {@link module:Findora-Network~Network#getUtxo|Network.getUtxo} for information about how to
    * fetch an asset record from the ledger server.
    * @param {any} record
    * @returns {AuthenticatedAssetRecord}
    */
    static from_json_record(record) {
        try {
            var ret = wasm.authenticatedassetrecord_from_json_record(addBorrowedObject(record));
            return AuthenticatedAssetRecord.__wrap(ret);
        } finally {
            heap[stack_pointer++] = undefined;
        }
    }
}
/**
* Use this struct to express a Bip44/Bip49 path.
*/
export class BipPath {

    static __wrap(ptr) {
        const obj = Object.create(BipPath.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_bippath_free(ptr);
    }
    /**
    * @param {number} coin
    * @param {number} account
    * @param {number} change
    * @param {number} address
    * @returns {BipPath}
    */
    static new(coin, account, change, address) {
        var ret = wasm.bippath_new(coin, account, change, address);
        return BipPath.__wrap(ret);
    }
}
/**
* This object represents an asset record owned by a ledger key pair.
* @see {@link module:Findora-Wasm.open_client_asset_record|open_client_asset_record} for information about how to decrypt an encrypted asset
* record.
*/
export class ClientAssetRecord {

    static __wrap(ptr) {
        const obj = Object.create(ClientAssetRecord.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_clientassetrecord_free(ptr);
    }
    /**
    * Builds a client record from a JSON-encoded JavaScript value.
    *
    * @param {JsValue} val - JSON-encoded autehtnicated asset record fetched from ledger server with the `utxo_sid/{sid}` route,
    * where `sid` can be fetched from the query server with the `get_owned_utxos/{address}` route.
    * Note: The first field of an asset record is `utxo`. See the example below.
    *
    * @example
    * "utxo":{
    *   "amount":{
    *     "NonConfidential":5
    *   },
    *  "asset_type":{
    *     "NonConfidential":[113,168,158,149,55,64,18,189,88,156,133,204,156,46,106,46,232,62,69,233,157,112,240,132,164,120,4,110,14,247,109,127]
    *   },
    *   "public_key":"Glf8dKF6jAPYHzR_PYYYfzaWqpYcMvnrIcazxsilmlA="
    * }
    *
    * @see {@link module:Findora-Network~Network#getUtxo|Network.getUtxo} for information about how to
    * fetch an asset record from the ledger server.
    * @param {any} val
    * @returns {ClientAssetRecord}
    */
    static from_json(val) {
        try {
            var ret = wasm.clientassetrecord_from_json(addBorrowedObject(val));
            return ClientAssetRecord.__wrap(ret);
        } finally {
            heap[stack_pointer++] = undefined;
        }
    }
    /**
    * ClientAssetRecord ==> JsValue
    * @returns {any}
    */
    to_json() {
        var ret = wasm.clientassetrecord_to_json(this.ptr);
        return takeObject(ret);
    }
}
/**
* Public key of a credential issuer.
*/
export class CredIssuerPublicKey {

    static __wrap(ptr) {
        const obj = Object.create(CredIssuerPublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credissuerpublickey_free(ptr);
    }
}
/**
* Secret key of a credential issuer.
*/
export class CredIssuerSecretKey {

    static __wrap(ptr) {
        const obj = Object.create(CredIssuerSecretKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credissuersecretkey_free(ptr);
    }
}
/**
* Public key of a credential user.
*/
export class CredUserPublicKey {

    static __wrap(ptr) {
        const obj = Object.create(CredUserPublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_creduserpublickey_free(ptr);
    }
}
/**
* Secret key of a credential user.
*/
export class CredUserSecretKey {

    static __wrap(ptr) {
        const obj = Object.create(CredUserSecretKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credusersecretkey_free(ptr);
    }
}
/**
* A user credential that can be used to selectively reveal credential attributes.
* @see {@link module:Findora-Wasm.wasm_credential_commit|wasm_credential_commit} for information about how to commit to a credential.
* @see {@link module:Findora-Wasm.wasm_credential_reveal|wasm_credential_reveal} for information about how to selectively reveal credential
* attributes.
*/
export class Credential {

    static __wrap(ptr) {
        const obj = Object.create(Credential.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credential_free(ptr);
    }
}
/**
* Commitment to a credential record.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
*/
export class CredentialCommitment {

    static __wrap(ptr) {
        const obj = Object.create(CredentialCommitment.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialcommitment_free(ptr);
    }
}
/**
* Commitment to a credential record, proof that the commitment is valid, and credential key that can be used
* to open a commitment.
*/
export class CredentialCommitmentData {

    static __wrap(ptr) {
        const obj = Object.create(CredentialCommitmentData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialcommitmentdata_free(ptr);
    }
    /**
    * Returns the underlying credential commitment.
    * @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
    * credential commitment.
    * @returns {CredentialCommitment}
    */
    get_commitment() {
        var ret = wasm.credentialcommitmentdata_get_commitment(this.ptr);
        return CredentialCommitment.__wrap(ret);
    }
    /**
    * Returns the underlying proof of knowledge that the credential is valid.
    * @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
    * credential commitment.
    * @returns {CredentialPoK}
    */
    get_pok() {
        var ret = wasm.credentialcommitmentdata_get_pok(this.ptr);
        return CredentialPoK.__wrap(ret);
    }
    /**
    * Returns the key used to generate the commitment.
    * @see {@link module:Findora-Wasm.wasm_credential_open_commitment|wasm_credential_open_commitment} for information about how to open a
    * credential commitment.
    * @returns {CredentialCommitmentKey}
    */
    get_commit_key() {
        var ret = wasm.credentialcommitmentdata_get_commit_key(this.ptr);
        return CredentialCommitmentKey.__wrap(ret);
    }
}
/**
* Key used to generate a credential commitment.
* @see {@link module:Findora-Wasm.wasm_credential_open_commitment|wasm_credential_open_commitment} for information about how to
* open a credential commitment.
*/
export class CredentialCommitmentKey {

    static __wrap(ptr) {
        const obj = Object.create(CredentialCommitmentKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialcommitmentkey_free(ptr);
    }
}
/**
* Key pair of a credential issuer.
*/
export class CredentialIssuerKeyPair {

    static __wrap(ptr) {
        const obj = Object.create(CredentialIssuerKeyPair.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialissuerkeypair_free(ptr);
    }
    /**
    * Returns the credential issuer's public key.
    * @returns {CredIssuerPublicKey}
    */
    get_pk() {
        var ret = wasm.credentialissuerkeypair_get_pk(this.ptr);
        return CredIssuerPublicKey.__wrap(ret);
    }
    /**
    * Returns the credential issuer's secret key.
    * @returns {CredIssuerSecretKey}
    */
    get_sk() {
        var ret = wasm.credentialissuerkeypair_get_sk(this.ptr);
        return CredIssuerSecretKey.__wrap(ret);
    }
    /**
    * Convert the key pair to a serialized value that can be used in the browser.
    * @returns {any}
    */
    to_json() {
        var ret = wasm.credentialissuerkeypair_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * Generate a key pair from a JSON-serialized JavaScript value.
    * @param {any} val
    * @returns {CredentialIssuerKeyPair}
    */
    static from_json(val) {
        try {
            var ret = wasm.credentialissuerkeypair_from_json(addBorrowedObject(val));
            return CredentialIssuerKeyPair.__wrap(ret);
        } finally {
            heap[stack_pointer++] = undefined;
        }
    }
}
/**
* Proof that a credential is a valid re-randomization of a credential signed by a certain asset
* issuer.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
*/
export class CredentialPoK {

    static __wrap(ptr) {
        const obj = Object.create(CredentialPoK.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialpok_free(ptr);
    }
}
/**
* Reveal signature of a credential record.
*/
export class CredentialRevealSig {

    static __wrap(ptr) {
        const obj = Object.create(CredentialRevealSig.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialrevealsig_free(ptr);
    }
    /**
    * Returns the underlying credential commitment.
    * @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
    * credential commitment.
    * @returns {CredentialCommitment}
    */
    get_commitment() {
        var ret = wasm.credentialcommitmentdata_get_commitment(this.ptr);
        return CredentialCommitment.__wrap(ret);
    }
    /**
    * Returns the underlying proof of knowledge that the credential is valid.
    * @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
    * credential commitment.
    * @returns {CredentialPoK}
    */
    get_pok() {
        var ret = wasm.credentialcommitmentdata_get_pok(this.ptr);
        return CredentialPoK.__wrap(ret);
    }
}
/**
* Signature of a credential record.
*/
export class CredentialSignature {

    static __wrap(ptr) {
        const obj = Object.create(CredentialSignature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialsignature_free(ptr);
    }
}
/**
* Key pair of a credential user.
*/
export class CredentialUserKeyPair {

    static __wrap(ptr) {
        const obj = Object.create(CredentialUserKeyPair.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_credentialuserkeypair_free(ptr);
    }
    /**
    * Returns the credential issuer's public key.
    * @returns {CredUserPublicKey}
    */
    get_pk() {
        var ret = wasm.credentialuserkeypair_get_pk(this.ptr);
        return CredUserPublicKey.__wrap(ret);
    }
    /**
    * Returns the credential issuer's secret key.
    * @returns {CredUserSecretKey}
    */
    get_sk() {
        var ret = wasm.credentialuserkeypair_get_sk(this.ptr);
        return CredUserSecretKey.__wrap(ret);
    }
    /**
    * Convert the key pair to a serialized value that can be used in the browser.
    * @returns {any}
    */
    to_json() {
        var ret = wasm.credentialuserkeypair_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * Generate a key pair from a JSON-serialized JavaScript value.
    * @param {any} val
    * @returns {CredentialUserKeyPair}
    */
    static from_json(val) {
        try {
            var ret = wasm.credentialuserkeypair_from_json(addBorrowedObject(val));
            return CredentialUserKeyPair.__wrap(ret);
        } finally {
            heap[stack_pointer++] = undefined;
        }
    }
}
/**
*/
export class FeeInputs {

    static __wrap(ptr) {
        const obj = Object.create(FeeInputs.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_feeinputs_free(ptr);
    }
    /**
    * @returns {FeeInputs}
    */
    static new() {
        var ret = wasm.feeinputs_new();
        return FeeInputs.__wrap(ret);
    }
    /**
    * @param {BigInt} am
    * @param {TxoRef} tr
    * @param {ClientAssetRecord} ar
    * @param {OwnerMemo | undefined} om
    * @param {XfrKeyPair} kp
    */
    append(am, tr, ar, om, kp) {
        uint64CvtShim[0] = am;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        _assertClass(tr, TxoRef);
        var ptr1 = tr.ptr;
        tr.ptr = 0;
        _assertClass(ar, ClientAssetRecord);
        var ptr2 = ar.ptr;
        ar.ptr = 0;
        let ptr3 = 0;
        if (!isLikeNone(om)) {
            _assertClass(om, OwnerMemo);
            ptr3 = om.ptr;
            om.ptr = 0;
        }
        _assertClass(kp, XfrKeyPair);
        var ptr4 = kp.ptr;
        kp.ptr = 0;
        wasm.feeinputs_append(this.ptr, low0, high0, ptr1, ptr2, ptr3, ptr4);
    }
    /**
    * @param {BigInt} am
    * @param {TxoRef} tr
    * @param {ClientAssetRecord} ar
    * @param {OwnerMemo | undefined} om
    * @param {XfrKeyPair} kp
    * @returns {FeeInputs}
    */
    append2(am, tr, ar, om, kp) {
        const ptr = this.__destroy_into_raw();
        uint64CvtShim[0] = am;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        _assertClass(tr, TxoRef);
        var ptr1 = tr.ptr;
        tr.ptr = 0;
        _assertClass(ar, ClientAssetRecord);
        var ptr2 = ar.ptr;
        ar.ptr = 0;
        let ptr3 = 0;
        if (!isLikeNone(om)) {
            _assertClass(om, OwnerMemo);
            ptr3 = om.ptr;
            om.ptr = 0;
        }
        _assertClass(kp, XfrKeyPair);
        var ptr4 = kp.ptr;
        kp.ptr = 0;
        var ret = wasm.feeinputs_append2(ptr, low0, high0, ptr1, ptr2, ptr3, ptr4);
        return FeeInputs.__wrap(ret);
    }
}
/**
* Asset owner memo. Contains information needed to decrypt an asset record.
* @see {@link module:Findora-Wasm.ClientAssetRecord|ClientAssetRecord} for more details about asset records.
*/
export class OwnerMemo {

    static __wrap(ptr) {
        const obj = Object.create(OwnerMemo.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ownermemo_free(ptr);
    }
    /**
    * Builds an owner memo from a JSON-serialized JavaScript value.
    * @param {JsValue} val - JSON owner memo fetched from query server with the `get_owner_memo/{sid}` route,
    * where `sid` can be fetched from the query server with the `get_owned_utxos/{address}` route. See the example below.
    *
    * @example
    * {
    *   "blind_share":[91,251,44,28,7,221,67,155,175,213,25,183,70,90,119,232,212,238,226,142,159,200,54,19,60,115,38,221,248,202,74,248],
    *   "lock":{"ciphertext":[119,54,117,136,125,133,112,193],"encoded_rand":"8KDql2JphPB5WLd7-aYE1bxTQAcweFSmrqymLvPDntM="}
    * }
    * @param {any} val
    * @returns {OwnerMemo}
    */
    static from_json(val) {
        try {
            var ret = wasm.ownermemo_from_json(addBorrowedObject(val));
            return OwnerMemo.__wrap(ret);
        } finally {
            heap[stack_pointer++] = undefined;
        }
    }
    /**
    * Creates a clone of the owner memo.
    * @returns {OwnerMemo}
    */
    clone() {
        var ret = wasm.ownermemo_clone(this.ptr);
        return OwnerMemo.__wrap(ret);
    }
}
/**
* Public parameters necessary for generating asset records. Generating this is expensive and
* should be done as infrequently as possible.
* @see {@link module:Findora-Wasm~TransactionBuilder#add_basic_issue_asset|add_basic_issue_asset}
* for information using public parameters to create issuance asset records.
*/
export class PublicParams {

    static __wrap(ptr) {
        const obj = Object.create(PublicParams.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_publicparams_free(ptr);
    }
    /**
    * Generates a new set of parameters.
    * @returns {PublicParams}
    */
    static new() {
        var ret = wasm.publicparams_new();
        return PublicParams.__wrap(ret);
    }
}
/**
* Stores threshold and weights for a multisignature requirement.
*/
export class SignatureRules {

    static __wrap(ptr) {
        const obj = Object.create(SignatureRules.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signaturerules_free(ptr);
    }
    /**
    * Creates a new set of co-signature rules.
    *
    * @param {BigInt} threshold - Minimum sum of signature weights that is required for an asset
    * transfer.
    * @param {JsValue} weights - Array of public key weights of the form `[["kAb...", BigInt(5)]]', where the
    * first element of each tuple is a base64 encoded public key and the second is the key's
    * associated weight.
    * @param {BigInt} threshold
    * @param {any} weights
    * @returns {SignatureRules}
    */
    static new(threshold, weights) {
        uint64CvtShim[0] = threshold;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ret = wasm.signaturerules_new(low0, high0, addHeapObject(weights));
        return SignatureRules.__wrap(ret);
    }
}
/**
* A collection of tracing policies. Use this object when constructing asset transfers to generate
* the correct tracing proofs for traceable assets.
*/
export class TracingPolicies {

    static __wrap(ptr) {
        const obj = Object.create(TracingPolicies.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_tracingpolicies_free(ptr);
    }
}
/**
* Tracing policy for asset transfers. Can be configured to track credentials, the asset type and
* amount, or both.
*/
export class TracingPolicy {

    static __wrap(ptr) {
        const obj = Object.create(TracingPolicy.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_tracingpolicy_free(ptr);
    }
    /**
    * @param {AssetTracerKeyPair} tracing_key
    * @returns {TracingPolicy}
    */
    static new_with_tracing(tracing_key) {
        _assertClass(tracing_key, AssetTracerKeyPair);
        var ret = wasm.tracingpolicy_new_with_tracing(tracing_key.ptr);
        return TracingPolicy.__wrap(ret);
    }
    /**
    * @param {AssetTracerKeyPair} tracing_key
    * @param {CredIssuerPublicKey} cred_issuer_key
    * @param {any} reveal_map
    * @param {boolean} tracing
    * @returns {TracingPolicy}
    */
    static new_with_identity_tracing(tracing_key, cred_issuer_key, reveal_map, tracing) {
        _assertClass(tracing_key, AssetTracerKeyPair);
        _assertClass(cred_issuer_key, CredIssuerPublicKey);
        var ret = wasm.tracingpolicy_new_with_identity_tracing(tracing_key.ptr, cred_issuer_key.ptr, addHeapObject(reveal_map), tracing);
        return TracingPolicy.__wrap(ret);
    }
}
/**
* Structure that allows users to construct arbitrary transactions.
*/
export class TransactionBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_transactionbuilder_free(ptr);
    }
    /**
    * @param am: amount to pay
    * @param kp: owner's XfrKeyPair
    * @param {XfrKeyPair} kp
    * @returns {TransactionBuilder}
    */
    add_fee_relative_auto(kp) {
        const ptr = this.__destroy_into_raw();
        _assertClass(kp, XfrKeyPair);
        var ptr0 = kp.ptr;
        kp.ptr = 0;
        var ret = wasm.transactionbuilder_add_fee_relative_auto(ptr, ptr0);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * Use this func to get the necessary infomations for generating `Relative Inputs`
    *
    * - TxoRef::Relative("Element index of the result")
    * - ClientAssetRecord::from_json("Element of the result")
    * @returns {any[]}
    */
    get_relative_outputs() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_get_relative_outputs(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var v0 = getArrayJsValueFromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 4);
            return v0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * As the last operation of any transaction,
    * add a static fee to the transaction.
    * @param {FeeInputs} inputs
    * @returns {TransactionBuilder}
    */
    add_fee(inputs) {
        const ptr = this.__destroy_into_raw();
        _assertClass(inputs, FeeInputs);
        var ptr0 = inputs.ptr;
        inputs.ptr = 0;
        var ret = wasm.transactionbuilder_add_fee(ptr, ptr0);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * A simple fee checker for mainnet v1.0.
    *
    * SEE [check_fee](ledger::data_model::Transaction::check_fee)
    * @returns {boolean}
    */
    check_fee() {
        var ret = wasm.transactionbuilder_check_fee(this.ptr);
        return ret !== 0;
    }
    /**
    * Create a new transaction builder.
    * @param {BigInt} seq_id - Unique sequence ID to prevent replay attacks.
    * @param {BigInt} seq_id
    * @returns {TransactionBuilder}
    */
    static new(seq_id) {
        uint64CvtShim[0] = seq_id;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ret = wasm.transactionbuilder_new(low0, high0);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransactionBuilder to add an asset definition operation to a transaction builder instance.
    * @example <caption> Error handling </caption>
    * try {
    *     await wasm.add_operation_create_asset(wasm.new_keypair(), "test_memo", wasm.random_asset_type(), wasm.AssetRules.default());
    * } catch (err) {
    *     console.log(err)
    * }
    *
    * @param {XfrKeyPair} key_pair -  Issuer XfrKeyPair.
    * @param {string} memo - Text field for asset definition.
    * @param {string} token_code - Optional Base64 string representing the token code of the asset to be issued.
    * If empty, a token code will be chosen at random.
    * @param {AssetRules} asset_rules - Asset rules object specifying which simple policies apply
    * to the asset.
    * @param {XfrKeyPair} key_pair
    * @param {string} memo
    * @param {string} token_code
    * @param {AssetRules} asset_rules
    * @returns {TransactionBuilder}
    */
    add_operation_create_asset(key_pair, memo, token_code, asset_rules) {
        const ptr = this.__destroy_into_raw();
        _assertClass(key_pair, XfrKeyPair);
        var ptr0 = passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passStringToWasm0(token_code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        _assertClass(asset_rules, AssetRules);
        var ptr2 = asset_rules.ptr;
        asset_rules.ptr = 0;
        var ret = wasm.transactionbuilder_add_operation_create_asset(ptr, key_pair.ptr, ptr0, len0, ptr1, len1, ptr2);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @ignore
    * @param {XfrKeyPair} key_pair
    * @param {string} memo
    * @param {string} token_code
    * @param {string} _policy_choice
    * @param {AssetRules} asset_rules
    * @returns {TransactionBuilder}
    */
    add_operation_create_asset_with_policy(key_pair, memo, token_code, _policy_choice, asset_rules) {
        const ptr = this.__destroy_into_raw();
        _assertClass(key_pair, XfrKeyPair);
        var ptr0 = passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passStringToWasm0(token_code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ptr2 = passStringToWasm0(_policy_choice, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        _assertClass(asset_rules, AssetRules);
        var ptr3 = asset_rules.ptr;
        asset_rules.ptr = 0;
        var ret = wasm.transactionbuilder_add_operation_create_asset_with_policy(ptr, key_pair.ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransactionBuilder to add an asset issuance to a transaction builder instance.
    *
    * Use this function for simple one-shot issuances.
    *
    * @param {XfrKeyPair} key_pair  - Issuer XfrKeyPair.
    * and types of traced assets.
    * @param {string} code - base64 string representing the token code of the asset to be issued.
    * @param {BigInt} seq_num - Issuance sequence number. Every subsequent issuance of a given asset type must have a higher sequence number than before.
    * @param {BigInt} amount - Amount to be issued.
    * @param {boolean} conf_amount - `true` means the asset amount is confidential, and `false` means it's nonconfidential.
    * @param {PublicParams} zei_params - Public parameters necessary to generate asset records.
    * @param {XfrKeyPair} key_pair
    * @param {string} code
    * @param {BigInt} seq_num
    * @param {BigInt} amount
    * @param {boolean} conf_amount
    * @param {PublicParams} zei_params
    * @returns {TransactionBuilder}
    */
    add_basic_issue_asset(key_pair, code, seq_num, amount, conf_amount, zei_params) {
        const ptr = this.__destroy_into_raw();
        _assertClass(key_pair, XfrKeyPair);
        var ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        uint64CvtShim[0] = seq_num;
        const low1 = u32CvtShim[0];
        const high1 = u32CvtShim[1];
        uint64CvtShim[0] = amount;
        const low2 = u32CvtShim[0];
        const high2 = u32CvtShim[1];
        _assertClass(zei_params, PublicParams);
        var ret = wasm.transactionbuilder_add_basic_issue_asset(ptr, key_pair.ptr, ptr0, len0, low1, high1, low2, high2, conf_amount, zei_params.ptr);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * Adds an operation to the transaction builder that adds a hash to the ledger's custom data
    * store.
    * @param {XfrKeyPair} auth_key_pair - Asset creator key pair.
    * @param {String} code - base64 string representing token code of the asset whose memo will be updated.
    * transaction validates.
    * @param {String} new_memo - The new asset memo.
    * @see {@link module:Findora-Wasm~AssetRules#set_updatable|AssetRules.set_updatable} for more information about how
    * to define an updatable asset.
    * @param {XfrKeyPair} auth_key_pair
    * @param {string} code
    * @param {string} new_memo
    * @returns {TransactionBuilder}
    */
    add_operation_update_memo(auth_key_pair, code, new_memo) {
        const ptr = this.__destroy_into_raw();
        _assertClass(auth_key_pair, XfrKeyPair);
        var ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passStringToWasm0(new_memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ret = wasm.transactionbuilder_add_operation_update_memo(ptr, auth_key_pair.ptr, ptr0, len0, ptr1, len1);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {XfrKeyPair} keypair
    * @param {BigInt} amount
    * @param {string} validator
    * @returns {TransactionBuilder}
    */
    add_operation_delegate(keypair, amount, validator) {
        const ptr = this.__destroy_into_raw();
        _assertClass(keypair, XfrKeyPair);
        uint64CvtShim[0] = amount;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ptr1 = passStringToWasm0(validator, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ret = wasm.transactionbuilder_add_operation_delegate(ptr, keypair.ptr, low0, high0, ptr1, len1);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {XfrKeyPair} keypair
    * @returns {TransactionBuilder}
    */
    add_operation_undelegate(keypair) {
        const ptr = this.__destroy_into_raw();
        _assertClass(keypair, XfrKeyPair);
        var ret = wasm.transactionbuilder_add_operation_undelegate(ptr, keypair.ptr);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {XfrKeyPair} keypair
    * @param {BigInt} am
    * @param {string} target_validator
    * @returns {TransactionBuilder}
    */
    add_operation_undelegate_partially(keypair, am, target_validator) {
        const ptr = this.__destroy_into_raw();
        _assertClass(keypair, XfrKeyPair);
        uint64CvtShim[0] = am;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ptr1 = passStringToWasm0(target_validator, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ret = wasm.transactionbuilder_add_operation_undelegate_partially(ptr, keypair.ptr, low0, high0, ptr1, len1);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {XfrKeyPair} keypair
    * @returns {TransactionBuilder}
    */
    add_operation_claim(keypair) {
        const ptr = this.__destroy_into_raw();
        _assertClass(keypair, XfrKeyPair);
        var ret = wasm.transactionbuilder_add_operation_claim(ptr, keypair.ptr);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {XfrKeyPair} keypair
    * @param {BigInt} am
    * @returns {TransactionBuilder}
    */
    add_operation_claim_custom(keypair, am) {
        const ptr = this.__destroy_into_raw();
        _assertClass(keypair, XfrKeyPair);
        uint64CvtShim[0] = am;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ret = wasm.transactionbuilder_add_operation_claim_custom(ptr, keypair.ptr, low0, high0);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * Adds an operation to the transaction builder that support transfer utxo asset to ethereum address.
    * @param {XfrKeyPair} keypair - Asset creator key pair.
    * @param {String} ethereum_address - The address to receive Ethereum assets.
    * @param {XfrKeyPair} keypair
    * @param {string} ethereum_address
    * @returns {TransactionBuilder}
    */
    add_operation_convert_account(keypair, ethereum_address) {
        const ptr = this.__destroy_into_raw();
        _assertClass(keypair, XfrKeyPair);
        var ptr0 = passStringToWasm0(ethereum_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.transactionbuilder_add_operation_convert_account(ptr, keypair.ptr, ptr0, len0);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * Adds a serialized transfer asset operation to a transaction builder instance.
    * @param {string} op - a JSON-serialized transfer operation.
    * @see {@link module:Findora-Wasm~TransferOperationBuilder} for details on constructing a transfer operation.
    * @throws Will throw an error if `op` fails to deserialize.
    * @param {string} op
    * @returns {TransactionBuilder}
    */
    add_transfer_operation(op) {
        const ptr = this.__destroy_into_raw();
        var ptr0 = passStringToWasm0(op, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.transactionbuilder_add_transfer_operation(ptr, ptr0, len0);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {XfrKeyPair} kp
    * @returns {TransactionBuilder}
    */
    sign(kp) {
        const ptr = this.__destroy_into_raw();
        _assertClass(kp, XfrKeyPair);
        var ret = wasm.transactionbuilder_sign(ptr, kp.ptr);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * Extracts the serialized form of a transaction.
    * @returns {string}
    */
    transaction() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_transaction(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * Calculates transaction handle.
    * @returns {string}
    */
    transaction_handle() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_transaction_handle(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * Fetches a client record from a transaction.
    * @param {number} idx - Record to fetch. Records are added to the transaction builder sequentially.
    * @param {number} idx
    * @returns {ClientAssetRecord}
    */
    get_owner_record(idx) {
        var ret = wasm.transactionbuilder_get_owner_record(this.ptr, idx);
        return ClientAssetRecord.__wrap(ret);
    }
    /**
    * Fetches an owner memo from a transaction
    * @param {number} idx - Owner memo to fetch. Owner memos are added to the transaction builder sequentially.
    * @param {number} idx
    * @returns {OwnerMemo | undefined}
    */
    get_owner_memo(idx) {
        var ret = wasm.transactionbuilder_get_owner_memo(this.ptr, idx);
        return ret === 0 ? undefined : OwnerMemo.__wrap(ret);
    }
}
/**
* Structure that enables clients to construct complex transfers.
*/
export class TransferOperationBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransferOperationBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_transferoperationbuilder_free(ptr);
    }
    /**
    * Create a new transfer operation builder.
    * @returns {TransferOperationBuilder}
    */
    static new() {
        var ret = wasm.transferoperationbuilder_new();
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransferOperationBuilder to add an input to a transfer operation builder.
    * @param {TxoRef} txo_ref - Absolute or relative utxo reference
    * @param {string} asset_record - Serialized client asset record to serve as transfer input. This record must exist on the
    * ledger for the transfer to be valid.
    * @param {OwnerMemo} owner_memo - Opening parameters.
    * @param tracing_key {AssetTracerKeyPair} - Tracing key, must be added to traceable
    * assets.
    * @param {XfrKeyPair} key - Key pair associated with the input.
    * @param {BigInt} amount - Amount of input record to transfer.
    * @see {@link module:Findora-Wasm~TxoRef#create_absolute_txo_ref|TxoRef.create_absolute_txo_ref}
    * or {@link module:Findora-Wasm~TxoRef#create_relative_txo_ref|TxoRef.create_relative_txo_ref} for details on txo
    * references.
    * @see {@link module:Findora-Network~Network#getUtxo|Network.getUtxo} for details on fetching blind asset records.
    * @throws Will throw an error if `oar` or `txo_ref` fail to deserialize.
    * @param {TxoRef} txo_ref
    * @param {ClientAssetRecord} asset_record
    * @param {OwnerMemo | undefined} owner_memo
    * @param {TracingPolicies} tracing_policies
    * @param {XfrKeyPair} key
    * @param {BigInt} amount
    * @returns {TransferOperationBuilder}
    */
    add_input_with_tracing(txo_ref, asset_record, owner_memo, tracing_policies, key, amount) {
        const ptr = this.__destroy_into_raw();
        _assertClass(txo_ref, TxoRef);
        var ptr0 = txo_ref.ptr;
        txo_ref.ptr = 0;
        _assertClass(asset_record, ClientAssetRecord);
        var ptr1 = asset_record.ptr;
        asset_record.ptr = 0;
        let ptr2 = 0;
        if (!isLikeNone(owner_memo)) {
            _assertClass(owner_memo, OwnerMemo);
            ptr2 = owner_memo.ptr;
            owner_memo.ptr = 0;
        }
        _assertClass(tracing_policies, TracingPolicies);
        _assertClass(key, XfrKeyPair);
        uint64CvtShim[0] = amount;
        const low3 = u32CvtShim[0];
        const high3 = u32CvtShim[1];
        var ret = wasm.transferoperationbuilder_add_input_with_tracing(ptr, ptr0, ptr1, ptr2, tracing_policies.ptr, key.ptr, low3, high3);
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransferOperationBuilder to add an input to a transfer operation builder.
    * @param {TxoRef} txo_ref - Absolute or relative utxo reference
    * @param {string} asset_record - Serialized client asset record to serve as transfer input. This record must exist on the
    * ledger for the transfer to be valid
    * @param {OwnerMemo} owner_memo - Opening parameters.
    * @param {XfrKeyPair} key - Key pair associated with the input.
    * @param {BigInt} amount - Amount of input record to transfer
    * or {@link module:Findora-Wasm~TxoRef#create_relative_txo_ref|TxoRef.create_relative_txo_ref} for details on txo
    * references.
    * @see {@link module:Findora-Network~Network#getUtxo|Network.getUtxo} for details on fetching blind asset records.
    * @throws Will throw an error if `oar` or `txo_ref` fail to deserialize.
    * @param {TxoRef} txo_ref
    * @param {ClientAssetRecord} asset_record
    * @param {OwnerMemo | undefined} owner_memo
    * @param {XfrKeyPair} key
    * @param {BigInt} amount
    * @returns {TransferOperationBuilder}
    */
    add_input_no_tracing(txo_ref, asset_record, owner_memo, key, amount) {
        const ptr = this.__destroy_into_raw();
        _assertClass(txo_ref, TxoRef);
        var ptr0 = txo_ref.ptr;
        txo_ref.ptr = 0;
        _assertClass(asset_record, ClientAssetRecord);
        let ptr1 = 0;
        if (!isLikeNone(owner_memo)) {
            _assertClass(owner_memo, OwnerMemo);
            ptr1 = owner_memo.ptr;
            owner_memo.ptr = 0;
        }
        _assertClass(key, XfrKeyPair);
        uint64CvtShim[0] = amount;
        const low2 = u32CvtShim[0];
        const high2 = u32CvtShim[1];
        var ret = wasm.transferoperationbuilder_add_input_no_tracing(ptr, ptr0, asset_record.ptr, ptr1, key.ptr, low2, high2);
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransferOperationBuilder to add an output to a transfer operation builder.
    *
    * @param {BigInt} amount - amount to transfer to the recipient.
    * @param {XfrPublicKey} recipient - public key of the recipient.
    * @param tracing_key {AssetTracerKeyPair} - Optional tracing key, must be added to traced
    * assets.
    * @param code {string} - String representation of the asset token code.
    * @param conf_amount {boolean} - `true` means the output's asset amount is confidential, and `false` means it's nonconfidential.
    * @param conf_type {boolean} - `true` means the output's asset type is confidential, and `false` means it's nonconfidential.
    * @throws Will throw an error if `code` fails to deserialize.
    * @param {BigInt} amount
    * @param {XfrPublicKey} recipient
    * @param {TracingPolicies} tracing_policies
    * @param {string} code
    * @param {boolean} conf_amount
    * @param {boolean} conf_type
    * @returns {TransferOperationBuilder}
    */
    add_output_with_tracing(amount, recipient, tracing_policies, code, conf_amount, conf_type) {
        const ptr = this.__destroy_into_raw();
        uint64CvtShim[0] = amount;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        _assertClass(recipient, XfrPublicKey);
        _assertClass(tracing_policies, TracingPolicies);
        var ptr1 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ret = wasm.transferoperationbuilder_add_output_with_tracing(ptr, low0, high0, recipient.ptr, tracing_policies.ptr, ptr1, len1, conf_amount, conf_type);
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransferOperationBuilder to add an output to a transfer operation builder.
    *
    * @param {BigInt} amount - amount to transfer to the recipient
    * @param {XfrPublicKey} recipient - public key of the recipient
    * @param code {string} - String representaiton of the asset token code
    * @param conf_amount {boolean} - `true` means the output's asset amount is confidential, and `false` means it's nonconfidential.
    * @param conf_type {boolean} - `true` means the output's asset type is confidential, and `false` means it's nonconfidential.
    * @throws Will throw an error if `code` fails to deserialize.
    * @param {BigInt} amount
    * @param {XfrPublicKey} recipient
    * @param {string} code
    * @param {boolean} conf_amount
    * @param {boolean} conf_type
    * @returns {TransferOperationBuilder}
    */
    add_output_no_tracing(amount, recipient, code, conf_amount, conf_type) {
        const ptr = this.__destroy_into_raw();
        uint64CvtShim[0] = amount;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        _assertClass(recipient, XfrPublicKey);
        var ptr1 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ret = wasm.transferoperationbuilder_add_output_no_tracing(ptr, low0, high0, recipient.ptr, ptr1, len1, conf_amount, conf_type);
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransferOperationBuilder to ensure the transfer inputs and outputs are balanced.
    * This function will add change outputs for all unspent portions of input records.
    * @throws Will throw an error if the transaction cannot be balanced.
    * @returns {TransferOperationBuilder}
    */
    balance() {
        const ptr = this.__destroy_into_raw();
        var ret = wasm.transferoperationbuilder_balance(ptr);
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransferOperationBuilder to finalize the transaction.
    *
    * @throws Will throw an error if input and output amounts do not add up.
    * @throws Will throw an error if not all record owners have signed the transaction.
    * @returns {TransferOperationBuilder}
    */
    create() {
        const ptr = this.__destroy_into_raw();
        var ret = wasm.transferoperationbuilder_create(ptr);
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * Wraps around TransferOperationBuilder to add a signature to the operation.
    *
    * All input owners must sign.
    *
    * @param {XfrKeyPair} kp - key pair of one of the input owners.
    * @param {XfrKeyPair} kp
    * @returns {TransferOperationBuilder}
    */
    sign(kp) {
        const ptr = this.__destroy_into_raw();
        _assertClass(kp, XfrKeyPair);
        var ret = wasm.transferoperationbuilder_sign(ptr, kp.ptr);
        return TransferOperationBuilder.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    builder() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transferoperationbuilder_builder(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * Wraps around TransferOperationBuilder to extract an operation expression as JSON.
    * @returns {string}
    */
    transaction() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transferoperationbuilder_transaction(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
* Indicates whether the TXO ref is an absolute or relative value.
*/
export class TxoRef {

    static __wrap(ptr) {
        const obj = Object.create(TxoRef.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_txoref_free(ptr);
    }
    /**
    * Creates a relative txo reference as a JSON string. Relative txo references are offset
    * backwards from the operation they appear in -- 0 is the most recent, (n-1) is the first output
    * of the transaction.
    *
    * Use relative txo indexing when referring to outputs of intermediate operations (e.g. a
    * transaction containing both an issuance and a transfer).
    *
    * # Arguments
    * @param {BigInt} idx -  Relative TXO (transaction output) SID.
    * @param {BigInt} idx
    * @returns {TxoRef}
    */
    static relative(idx) {
        uint64CvtShim[0] = idx;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ret = wasm.txoref_relative(low0, high0);
        return TxoRef.__wrap(ret);
    }
    /**
    * Creates an absolute transaction reference as a JSON string.
    *
    * Use absolute txo indexing when referring to an output that has been assigned a utxo index (i.e.
    * when the utxo has been committed to the ledger in an earlier transaction).
    *
    * # Arguments
    * @param {BigInt} idx -  Txo (transaction output) SID.
    * @param {BigInt} idx
    * @returns {TxoRef}
    */
    static absolute(idx) {
        uint64CvtShim[0] = idx;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        var ret = wasm.txoref_absolute(low0, high0);
        return TxoRef.__wrap(ret);
    }
}
/**
*/
export class XfrKeyPair {

    static __wrap(ptr) {
        const obj = Object.create(XfrKeyPair.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_xfrkeypair_free(ptr);
    }
    /**
    */
    get pub_key() {
        var ret = wasm.__wbg_get_xfrkeypair_pub_key(this.ptr);
        return XfrPublicKey.__wrap(ret);
    }
    /**
    * @param {XfrPublicKey} arg0
    */
    set pub_key(arg0) {
        _assertClass(arg0, XfrPublicKey);
        var ptr0 = arg0.ptr;
        arg0.ptr = 0;
        wasm.__wbg_set_xfrkeypair_pub_key(this.ptr, ptr0);
    }
}
/**
*/
export class XfrPublicKey {

    static __wrap(ptr) {
        const obj = Object.create(XfrPublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_xfrpublickey_free(ptr);
    }
}

export function __wbindgen_json_parse(arg0, arg1) {
    var ret = JSON.parse(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

export function __wbindgen_json_serialize(arg0, arg1) {
    const obj = getObject(arg1);
    var ret = JSON.stringify(obj === undefined ? null : obj);
    var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

export function __wbindgen_string_new(arg0, arg1) {
    var ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
};

export function __wbindgen_object_drop_ref(arg0) {
    takeObject(arg0);
};

export function __wbg_getRandomValues_98117e9a7e993920() { return handleError(function (arg0, arg1) {
    getObject(arg0).getRandomValues(getObject(arg1));
}, arguments) };

export function __wbg_randomFillSync_64cc7d048f228ca8() { return handleError(function (arg0, arg1, arg2) {
    getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
}, arguments) };

export function __wbg_process_2f24d6544ea7b200(arg0) {
    var ret = getObject(arg0).process;
    return addHeapObject(ret);
};

export function __wbindgen_is_object(arg0) {
    const val = getObject(arg0);
    var ret = typeof(val) === 'object' && val !== null;
    return ret;
};

export function __wbg_versions_6164651e75405d4a(arg0) {
    var ret = getObject(arg0).versions;
    return addHeapObject(ret);
};

export function __wbg_node_4b517d861cbcb3bc(arg0) {
    var ret = getObject(arg0).node;
    return addHeapObject(ret);
};

export function __wbindgen_is_string(arg0) {
    var ret = typeof(getObject(arg0)) === 'string';
    return ret;
};

export function __wbg_crypto_98fc271021c7d2ad(arg0) {
    var ret = getObject(arg0).crypto;
    return addHeapObject(ret);
};

export function __wbg_msCrypto_a2cdb043d2bfe57f(arg0) {
    var ret = getObject(arg0).msCrypto;
    return addHeapObject(ret);
};

export function __wbg_modulerequire_3440a4bcf44437db() { return handleError(function (arg0, arg1) {
    var ret = module.require(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
}, arguments) };

export function __wbg_self_86b4b13392c7af56() { return handleError(function () {
    var ret = self.self;
    return addHeapObject(ret);
}, arguments) };

export function __wbg_crypto_b8c92eaac23d0d80(arg0) {
    var ret = getObject(arg0).crypto;
    return addHeapObject(ret);
};

export function __wbg_msCrypto_9ad6677321a08dd8(arg0) {
    var ret = getObject(arg0).msCrypto;
    return addHeapObject(ret);
};

export function __wbindgen_is_undefined(arg0) {
    var ret = getObject(arg0) === undefined;
    return ret;
};

export function __wbg_static_accessor_MODULE_452b4680e8614c81() {
    var ret = module;
    return addHeapObject(ret);
};

export function __wbg_require_f5521a5b85ad2542(arg0, arg1, arg2) {
    var ret = getObject(arg0).require(getStringFromWasm0(arg1, arg2));
    return addHeapObject(ret);
};

export function __wbg_getRandomValues_dd27e6b0652b3236(arg0) {
    var ret = getObject(arg0).getRandomValues;
    return addHeapObject(ret);
};

export function __wbg_getRandomValues_e57c9b75ddead065(arg0, arg1) {
    getObject(arg0).getRandomValues(getObject(arg1));
};

export function __wbg_randomFillSync_d2ba53160aec6aba(arg0, arg1, arg2) {
    getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
};

export function __wbg_newnoargs_be86524d73f67598(arg0, arg1) {
    var ret = new Function(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

export function __wbg_call_888d259a5fefc347() { return handleError(function (arg0, arg1) {
    var ret = getObject(arg0).call(getObject(arg1));
    return addHeapObject(ret);
}, arguments) };

export function __wbindgen_object_clone_ref(arg0) {
    var ret = getObject(arg0);
    return addHeapObject(ret);
};

export function __wbg_self_c6fbdfc2918d5e58() { return handleError(function () {
    var ret = self.self;
    return addHeapObject(ret);
}, arguments) };

export function __wbg_window_baec038b5ab35c54() { return handleError(function () {
    var ret = window.window;
    return addHeapObject(ret);
}, arguments) };

export function __wbg_globalThis_3f735a5746d41fbd() { return handleError(function () {
    var ret = globalThis.globalThis;
    return addHeapObject(ret);
}, arguments) };

export function __wbg_global_1bc0b39582740e95() { return handleError(function () {
    var ret = global.global;
    return addHeapObject(ret);
}, arguments) };

export function __wbg_buffer_397eaa4d72ee94dd(arg0) {
    var ret = getObject(arg0).buffer;
    return addHeapObject(ret);
};

export function __wbg_new_a7ce447f15ff496f(arg0) {
    var ret = new Uint8Array(getObject(arg0));
    return addHeapObject(ret);
};

export function __wbg_set_969ad0a60e51d320(arg0, arg1, arg2) {
    getObject(arg0).set(getObject(arg1), arg2 >>> 0);
};

export function __wbg_length_1eb8fc608a0d4cdb(arg0) {
    var ret = getObject(arg0).length;
    return ret;
};

export function __wbg_newwithlength_929232475839a482(arg0) {
    var ret = new Uint8Array(arg0 >>> 0);
    return addHeapObject(ret);
};

export function __wbg_subarray_8b658422a224f479(arg0, arg1, arg2) {
    var ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
    return addHeapObject(ret);
};

export function __wbindgen_debug_string(arg0, arg1) {
    var ret = debugString(getObject(arg1));
    var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

export function __wbindgen_throw(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

export function __wbindgen_rethrow(arg0) {
    throw takeObject(arg0);
};

export function __wbindgen_memory() {
    var ret = wasm.memory;
    return addHeapObject(ret);
};

