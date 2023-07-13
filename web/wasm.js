let wasm;

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

const cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachedUint8Memory0 = null;

function getUint8Memory0() {
    if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = new TextEncoder('utf-8');

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

let cachedInt32Memory0 = null;

function getInt32Memory0() {
    if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
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
* Creates a new asset code with prefixing-hashing the original code to query the ledger.
* @param {string} asset_code_string
* @returns {string}
*/
export function hash_asset_code(asset_code_string) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(asset_code_string, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.hash_asset_code(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr1, len1);
    }
}

let stack_pointer = 128;

function addBorrowedObject(obj) {
    if (stack_pointer == 1) throw new Error('out of js stack');
    heap[--stack_pointer] = obj;
    return stack_pointer;
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
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr0 = r0;
        var len0 = r1;
        if (r3) {
            ptr0 = 0; len0 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr0, len0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
        wasm.__wbindgen_free(ptr0, len0);
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(state_commitment, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(authenticated_txn, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.verify_authenticated_txn(retptr, ptr0, len0, ptr1, len1);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return r0 !== 0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* ...
* @returns {XfrPublicKey}
*/
export function get_null_pk() {
    const ret = wasm.get_null_pk();
    return XfrPublicKey.__wrap(ret);
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

let cachedUint32Memory0 = null;

function getUint32Memory0() {
    if (cachedUint32Memory0 === null || cachedUint32Memory0.byteLength === 0) {
        cachedUint32Memory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachedUint32Memory0;
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

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
* Build transfer from account balance to utxo tx.
* @param {XfrPublicKey} recipient - UTXO Asset receiver.
* @param {u64} amount - Transfer amount.
* @param {string} sk - Ethereum wallet private key.
* @param {u64} nonce - Transaction nonce for sender.
* @param {XfrPublicKey} recipient
* @param {bigint} amount
* @param {string} sk
* @param {bigint} nonce
* @returns {string}
*/
export function transfer_to_utxo_from_account(recipient, amount, sk, nonce) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(recipient, XfrPublicKey);
        var ptr0 = recipient.__destroy_into_raw();
        const ptr1 = passStringToWasm0(sk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.transfer_to_utxo_from_account(retptr, ptr0, amount, ptr1, len1, nonce);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr2, len2);
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
        const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.recover_sk_from_mnemonic(retptr, ptr0, len0, ptr1, len1);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr2, len2);
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
        const ptr0 = passStringToWasm0(sk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.recover_address_from_sk(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr1, len1);
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
        const ptr0 = passStringToWasm0(address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.get_serialized_address(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr1, len1);
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(record, ClientAssetRecord);
        let ptr0 = 0;
        if (!isLikeNone(owner_memo)) {
            _assertClass(owner_memo, OwnerMemo);
            ptr0 = owner_memo.__destroy_into_raw();
        }
        _assertClass(keypair, XfrKeyPair);
        wasm.open_client_asset_record(retptr, record.ptr, ptr0, keypair.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    const ret = wasm.new_keypair();
    return XfrKeyPair.__wrap(ret);
}

/**
* Generates a new keypair deterministically from a seed string and an optional name.
* @param {string} seed_str
* @param {string | undefined} name
* @returns {XfrKeyPair}
*/
export function new_keypair_from_seed(seed_str, name) {
    const ptr0 = passStringToWasm0(seed_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(name) ? 0 : passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.new_keypair_from_seed(ptr0, len0, ptr1, len1);
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(pk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.public_key_from_base64(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return XfrPublicKey.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    const ptr0 = passStringToWasm0(str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.keypair_from_str(ptr0, len0);
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
    const ret = wasm.wasm_credential_issuer_key_gen(addHeapObject(attributes));
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(issuer_pub_key, CredIssuerPublicKey);
        _assertClass(commitment, CredentialCommitment);
        _assertClass(pok, CredentialPoK);
        _assertClass(xfr_pk, XfrPublicKey);
        wasm.wasm_credential_verify_commitment(retptr, issuer_pub_key.ptr, commitment.ptr, pok.ptr, xfr_pk.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        if (r1) {
            throw takeObject(r0);
        }
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(user_secret_key, CredUserSecretKey);
        _assertClass(credential, Credential);
        _assertClass(key, CredentialCommitmentKey);
        wasm.wasm_credential_open_commitment(retptr, user_secret_key.ptr, credential.ptr, key.ptr, addHeapObject(reveal_fields));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return CredentialPoK.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    const ret = wasm.wasm_credential_user_key_gen(issuer_pub_key.ptr);
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(issuer_secret_key, CredIssuerSecretKey);
        _assertClass(user_public_key, CredUserPublicKey);
        wasm.wasm_credential_sign(retptr, issuer_secret_key.ptr, user_public_key.ptr, addHeapObject(attributes));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return CredentialSignature.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
        const ret = wasm.create_credential(issuer_public_key.ptr, signature.ptr, addBorrowedObject(attributes));
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(user_secret_key, CredUserSecretKey);
        _assertClass(user_public_key, XfrPublicKey);
        _assertClass(credential, Credential);
        wasm.wasm_credential_commit(retptr, user_secret_key.ptr, user_public_key.ptr, credential.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return CredentialCommitmentData.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(user_sk, CredUserSecretKey);
        _assertClass(credential, Credential);
        wasm.wasm_credential_reveal(retptr, user_sk.ptr, credential.ptr, addHeapObject(reveal_fields));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return CredentialRevealSig.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(issuer_pub_key, CredIssuerPublicKey);
        _assertClass(commitment, CredentialCommitment);
        _assertClass(pok, CredentialPoK);
        wasm.wasm_credential_verify(retptr, issuer_pub_key.ptr, addHeapObject(attributes), commitment.ptr, pok.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        if (r1) {
            throw takeObject(r0);
        }
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(tracer_keypair, AssetTracerKeyPair);
        wasm.trace_assets(retptr, addHeapObject(xfr_body), tracer_keypair.ptr, addHeapObject(_candidate_assets));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.public_key_from_bech32(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return XfrPublicKey.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {string} pk
* @returns {string}
*/
export function bech32_to_base64(pk) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(pk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.bech32_to_base64(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr1, len1);
    }
}

/**
* @param {string} pk
* @returns {string}
*/
export function base64_to_bech32(pk) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(pk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base64_to_bech32(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr1, len1);
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
        const ptr0 = passStringToWasm0(key_pair, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
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

/**
* @param {Uint8Array} enc_key_pair
* @param {string} password
* @returns {string}
*/
export function decryption_pbkdf2_aes256gcm(enc_key_pair, password) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(enc_key_pair, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
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
    const ptr0 = passStringToWasm0(sk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.create_keypair_from_secret(ptr0, len0);
    return ret === 0 ? undefined : XfrKeyPair.__wrap(ret);
}

/**
* @param {XfrKeyPair} kp
* @returns {XfrPublicKey}
*/
export function get_pk_from_keypair(kp) {
    _assertClass(kp, XfrKeyPair);
    const ret = wasm.get_pk_from_keypair(kp.ptr);
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
        const ptr0 = passStringToWasm0(lang, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.generate_mnemonic_custom(retptr, wordslen, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(ptr1, len1);
    }
}

/**
* Restore the XfrKeyPair from a mnemonic with a default bip44-path,
* that is "m/44'/917'/0'/0/0" ("m/44'/coin'/account'/change/address").
* @param {string} phrase
* @returns {XfrKeyPair}
*/
export function restore_keypair_from_mnemonic_default(phrase) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.restore_keypair_from_mnemonic_default(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return XfrKeyPair.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(lang, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        _assertClass(path, BipPath);
        wasm.restore_keypair_from_mnemonic_bip44(retptr, ptr0, len0, ptr1, len1, path.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return XfrKeyPair.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(lang, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        _assertClass(path, BipPath);
        wasm.restore_keypair_from_mnemonic_bip49(retptr, ptr0, len0, ptr1, len1, path.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return XfrKeyPair.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
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
* @returns {bigint}
*/
export function fra_get_minimal_fee() {
    const ret = wasm.fra_get_minimal_fee();
    return BigInt.asUintN(64, ret);
}

/**
* The destination for fee to be transfered to.
* @returns {XfrPublicKey}
*/
export function fra_get_dest_pubkey() {
    const ret = wasm.fra_get_dest_pubkey();
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
* @returns {bigint}
*/
export function get_delegation_min_amount() {
    const ret = wasm.get_delegation_min_amount();
    return BigInt.asUintN(64, ret);
}

/**
* @returns {bigint}
*/
export function get_delegation_max_amount() {
    const ret = wasm.get_delegation_max_amount();
    return BigInt.asUintN(64, ret);
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
        const ret = wasm.assetrules_new();
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
        const ret = wasm.assetrules_add_tracing_policy(ptr, policy.ptr);
        return AssetRules.__wrap(ret);
    }
    /**
    * Set a cap on the number of units of this asset that can be issued.
    * @param {BigInt} max_units - Maximum number of units that can be issued.
    * @param {bigint} max_units
    * @returns {AssetRules}
    */
    set_max_units(max_units) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.assetrules_set_max_units(ptr, max_units);
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
        const ret = wasm.assetrules_set_transferable(ptr, transferable);
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
        const ret = wasm.assetrules_set_updatable(ptr, updatable);
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
        var ptr0 = multisig_rules.__destroy_into_raw();
        const ret = wasm.assetrules_set_transfer_multisig_rules(ptr, ptr0);
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.assetrules_set_decimals(retptr, ptr, decimals);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AssetRules.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        const ret = wasm.assettracerkeypair_new();
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
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.assettype_from_json(retptr, addBorrowedObject(json));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AssetType.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
    * Fetch the tracing policies associated with this asset type.
    * @returns {TracingPolicies}
    */
    get_tracing_policies() {
        const ret = wasm.assettype_get_tracing_policies(this.ptr);
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
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(state_commitment, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.authenticatedassetrecord_is_valid(retptr, this.ptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.authenticatedassetrecord_from_json_record(retptr, addBorrowedObject(record));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AuthenticatedAssetRecord.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
}
/**
* The wrapped struct for `ark_bls12_381::Fq`
*/
export class BLSFq {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blsfq_free(ptr);
    }
}
/**
* The wrapped struct for ark_bls12_381::G1Projective
*/
export class BLSG1 {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blsg1_free(ptr);
    }
}
/**
* The wrapped struct for `ark_bls12_381::G2Projective`
*/
export class BLSG2 {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blsg2_free(ptr);
    }
}
/**
* The wrapped struct for [`Fp12<ark_bls12_381::Fq12Parameters>`](https://docs.rs/ark-bls12-381/0.3.0/ark_bls12_381/fq12/struct.Fq12Parameters.html),
* which is the pairing result
*/
export class BLSGt {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blsgt_free(ptr);
    }
}
/**
* The wrapped struct for `ark_bls12_381::Fr`
*/
export class BLSScalar {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blsscalar_free(ptr);
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
        const ret = wasm.bippath_new(coin, account, change, address);
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
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.clientassetrecord_from_json(retptr, addBorrowedObject(val));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return ClientAssetRecord.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
    * ClientAssetRecord ==> JsValue
    * @returns {any}
    */
    to_json() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.clientassetrecord_to_json(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        const ret = wasm.credentialcommitmentdata_get_commitment(this.ptr);
        return CredentialCommitment.__wrap(ret);
    }
    /**
    * Returns the underlying proof of knowledge that the credential is valid.
    * @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
    * credential commitment.
    * @returns {CredentialPoK}
    */
    get_pok() {
        const ret = wasm.credentialcommitmentdata_get_pok(this.ptr);
        return CredentialPoK.__wrap(ret);
    }
    /**
    * Returns the key used to generate the commitment.
    * @see {@link module:Findora-Wasm.wasm_credential_open_commitment|wasm_credential_open_commitment} for information about how to open a
    * credential commitment.
    * @returns {CredentialCommitmentKey}
    */
    get_commit_key() {
        const ret = wasm.credentialcommitmentdata_get_commit_key(this.ptr);
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
        const ret = wasm.credentialissuerkeypair_get_pk(this.ptr);
        return CredIssuerPublicKey.__wrap(ret);
    }
    /**
    * Returns the credential issuer's secret key.
    * @returns {CredIssuerSecretKey}
    */
    get_sk() {
        const ret = wasm.credentialissuerkeypair_get_sk(this.ptr);
        return CredIssuerSecretKey.__wrap(ret);
    }
    /**
    * Convert the key pair to a serialized value that can be used in the browser.
    * @returns {any}
    */
    to_json() {
        const ret = wasm.credentialissuerkeypair_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * Generate a key pair from a JSON-serialized JavaScript value.
    * @param {any} val
    * @returns {CredentialIssuerKeyPair}
    */
    static from_json(val) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.credentialissuerkeypair_from_json(retptr, addBorrowedObject(val));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return CredentialIssuerKeyPair.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
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
        const ret = wasm.credentialrevealsig_get_commitment(this.ptr);
        return CredentialCommitment.__wrap(ret);
    }
    /**
    * Returns the underlying proof of knowledge that the credential is valid.
    * @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
    * credential commitment.
    * @returns {CredentialPoK}
    */
    get_pok() {
        const ret = wasm.credentialrevealsig_get_pok(this.ptr);
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
        const ret = wasm.credentialuserkeypair_get_pk(this.ptr);
        return CredUserPublicKey.__wrap(ret);
    }
    /**
    * Returns the credential issuer's secret key.
    * @returns {CredUserSecretKey}
    */
    get_sk() {
        const ret = wasm.credentialuserkeypair_get_sk(this.ptr);
        return CredUserSecretKey.__wrap(ret);
    }
    /**
    * Convert the key pair to a serialized value that can be used in the browser.
    * @returns {any}
    */
    to_json() {
        const ret = wasm.credentialuserkeypair_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * Generate a key pair from a JSON-serialized JavaScript value.
    * @param {any} val
    * @returns {CredentialUserKeyPair}
    */
    static from_json(val) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.credentialuserkeypair_from_json(retptr, addBorrowedObject(val));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return CredentialUserKeyPair.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
}
/**
* The wrapped struct for `ark_ed25519::EdwardsProjective`
*/
export class Ed25519Point {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ed25519point_free(ptr);
    }
}
/**
* The wrapped struct for `ark_ed25519::Fr`
*/
export class Ed25519Scalar {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ed25519scalar_free(ptr);
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
        const ret = wasm.feeinputs_new();
        return FeeInputs.__wrap(ret);
    }
    /**
    * @param {bigint} am
    * @param {TxoRef} tr
    * @param {ClientAssetRecord} ar
    * @param {OwnerMemo | undefined} om
    * @param {XfrKeyPair} kp
    */
    append(am, tr, ar, om, kp) {
        _assertClass(tr, TxoRef);
        var ptr0 = tr.__destroy_into_raw();
        _assertClass(ar, ClientAssetRecord);
        var ptr1 = ar.__destroy_into_raw();
        let ptr2 = 0;
        if (!isLikeNone(om)) {
            _assertClass(om, OwnerMemo);
            ptr2 = om.__destroy_into_raw();
        }
        _assertClass(kp, XfrKeyPair);
        var ptr3 = kp.__destroy_into_raw();
        wasm.feeinputs_append(this.ptr, am, ptr0, ptr1, ptr2, ptr3);
    }
    /**
    * @param {bigint} am
    * @param {TxoRef} tr
    * @param {ClientAssetRecord} ar
    * @param {OwnerMemo | undefined} om
    * @param {XfrKeyPair} kp
    * @returns {FeeInputs}
    */
    append2(am, tr, ar, om, kp) {
        const ptr = this.__destroy_into_raw();
        _assertClass(tr, TxoRef);
        var ptr0 = tr.__destroy_into_raw();
        _assertClass(ar, ClientAssetRecord);
        var ptr1 = ar.__destroy_into_raw();
        let ptr2 = 0;
        if (!isLikeNone(om)) {
            _assertClass(om, OwnerMemo);
            ptr2 = om.__destroy_into_raw();
        }
        _assertClass(kp, XfrKeyPair);
        var ptr3 = kp.__destroy_into_raw();
        const ret = wasm.feeinputs_append2(ptr, am, ptr0, ptr1, ptr2, ptr3);
        return FeeInputs.__wrap(ret);
    }
}
/**
* The wrapped struct for `ark_ed_on_bls12_381::Fr`
*/
export class JubjubScalar {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_jubjubscalar_free(ptr);
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
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.ownermemo_from_json(retptr, addBorrowedObject(val));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return OwnerMemo.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
    * Creates a clone of the owner memo.
    * @returns {OwnerMemo}
    */
    clone() {
        const ret = wasm.ownermemo_clone(this.ptr);
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
        const ret = wasm.publicparams_new();
        return PublicParams.__wrap(ret);
    }
}
/**
* The wrapped struct for `ark_secp256k1::Projective`
*/
export class SECP256K1G1 {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1g1_free(ptr);
    }
}
/**
* The wrapped struct for `ark_secp256k1::Fr`
*/
export class SECP256K1Scalar {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1scalar_free(ptr);
    }
}
/**
* The wrapped struct for `ark_secq256k1::Projective`
*/
export class SECQ256K1G1 {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secq256k1g1_free(ptr);
    }
}
/**
* The wrapped struct for `ark_secq256k1::Fr`
*/
export class SECQ256K1Scalar {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secq256k1scalar_free(ptr);
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
    * @param {bigint} threshold
    * @param {any} weights
    * @returns {SignatureRules}
    */
    static new(threshold, weights) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.signaturerules_new(retptr, threshold, addHeapObject(weights));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return SignatureRules.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        const ret = wasm.tracingpolicy_new_with_tracing(tracing_key.ptr);
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
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(tracing_key, AssetTracerKeyPair);
            _assertClass(cred_issuer_key, CredIssuerPublicKey);
            wasm.tracingpolicy_new_with_identity_tracing(retptr, tracing_key.ptr, cred_issuer_key.ptr, addHeapObject(reveal_map), tracing);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TracingPolicy.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(kp, XfrKeyPair);
            var ptr0 = kp.__destroy_into_raw();
            wasm.transactionbuilder_add_fee_relative_auto(retptr, ptr, ptr0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(inputs, FeeInputs);
            var ptr0 = inputs.__destroy_into_raw();
            wasm.transactionbuilder_add_fee(retptr, ptr, ptr0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * A simple fee checker for mainnet v1.0.
    *
    * SEE [check_fee](ledger::data_model::Transaction::check_fee)
    * @returns {boolean}
    */
    check_fee() {
        const ret = wasm.transactionbuilder_check_fee(this.ptr);
        return ret !== 0;
    }
    /**
    * Create a new transaction builder.
    * @param {BigInt} seq_id - Unique sequence ID to prevent replay attacks.
    * @param {bigint} seq_id
    * @returns {TransactionBuilder}
    */
    static new(seq_id) {
        const ret = wasm.transactionbuilder_new(seq_id);
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key_pair, XfrKeyPair);
            const ptr0 = passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(token_code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            _assertClass(asset_rules, AssetRules);
            var ptr2 = asset_rules.__destroy_into_raw();
            wasm.transactionbuilder_add_operation_create_asset(retptr, ptr, key_pair.ptr, ptr0, len0, ptr1, len1, ptr2);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key_pair, XfrKeyPair);
            const ptr0 = passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(token_code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(_policy_choice, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            _assertClass(asset_rules, AssetRules);
            var ptr3 = asset_rules.__destroy_into_raw();
            wasm.transactionbuilder_add_operation_create_asset_with_policy(retptr, ptr, key_pair.ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
    * @param {bigint} seq_num
    * @param {bigint} amount
    * @param {boolean} conf_amount
    * @returns {TransactionBuilder}
    */
    add_basic_issue_asset(key_pair, code, seq_num, amount, conf_amount) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key_pair, XfrKeyPair);
            const ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_basic_issue_asset(retptr, ptr, key_pair.ptr, ptr0, len0, seq_num, amount, conf_amount);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(auth_key_pair, XfrKeyPair);
            const ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(new_memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_operation_update_memo(retptr, ptr, auth_key_pair.ptr, ptr0, len0, ptr1, len1);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {XfrKeyPair} keypair
    * @param {bigint} amount
    * @param {string} validator
    * @returns {TransactionBuilder}
    */
    add_operation_delegate(keypair, amount, validator) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keypair, XfrKeyPair);
            const ptr0 = passStringToWasm0(validator, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_operation_delegate(retptr, ptr, keypair.ptr, amount, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {XfrKeyPair} keypair
    * @returns {TransactionBuilder}
    */
    add_operation_undelegate(keypair) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keypair, XfrKeyPair);
            wasm.transactionbuilder_add_operation_undelegate(retptr, ptr, keypair.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {XfrKeyPair} keypair
    * @param {bigint} am
    * @param {string} target_validator
    * @returns {TransactionBuilder}
    */
    add_operation_undelegate_partially(keypair, am, target_validator) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keypair, XfrKeyPair);
            const ptr0 = passStringToWasm0(target_validator, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_operation_undelegate_partially(retptr, ptr, keypair.ptr, am, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {XfrKeyPair} keypair
    * @param {Uint8Array} td_addr
    * @returns {TransactionBuilder}
    */
    add_operation_claim(keypair, td_addr) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keypair, XfrKeyPair);
            const ptr0 = passArray8ToWasm0(td_addr, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_operation_claim(retptr, ptr, keypair.ptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {XfrKeyPair} keypair
    * @param {Uint8Array} td_addr
    * @param {bigint} am
    * @returns {TransactionBuilder}
    */
    add_operation_claim_custom(keypair, td_addr, am) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keypair, XfrKeyPair);
            const ptr0 = passArray8ToWasm0(td_addr, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_operation_claim_custom(retptr, ptr, keypair.ptr, ptr0, len0, am);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Adds an operation to the transaction builder that support transfer utxo asset to ethereum address.
    * @param {XfrKeyPair} keypair - Asset creator key pair.
    * @param {String} ethereum_address - The address to receive Ethereum assets.
    * @param {XfrKeyPair} keypair
    * @param {string} ethereum_address
    * @param {bigint} amount
    * @param {string | undefined} asset
    * @param {string | undefined} lowlevel_data
    * @returns {TransactionBuilder}
    */
    add_operation_convert_account(keypair, ethereum_address, amount, asset, lowlevel_data) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keypair, XfrKeyPair);
            const ptr0 = passStringToWasm0(ethereum_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(asset) ? 0 : passStringToWasm0(asset, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(lowlevel_data) ? 0 : passStringToWasm0(lowlevel_data, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len2 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_operation_convert_account(retptr, ptr, keypair.ptr, ptr0, len0, amount, ptr1, len1, ptr2, len2);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(op, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transactionbuilder_add_transfer_operation(retptr, ptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Do nothing, compatible with frontend
    * @returns {TransactionBuilder}
    */
    build() {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_build(retptr, ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {XfrKeyPair} kp
    * @returns {TransactionBuilder}
    */
    sign(kp) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(kp, XfrKeyPair);
            wasm.transactionbuilder_sign(retptr, ptr, kp.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {XfrKeyPair} kp
    * @returns {TransactionBuilder}
    */
    sign_origin(kp) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(kp, XfrKeyPair);
            wasm.transactionbuilder_sign_origin(retptr, ptr, kp.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        const ret = wasm.transactionbuilder_get_owner_record(this.ptr, idx);
        return ClientAssetRecord.__wrap(ret);
    }
    /**
    * Fetches an owner memo from a transaction
    * @param {number} idx - Owner memo to fetch. Owner memos are added to the transaction builder sequentially.
    * @param {number} idx
    * @returns {OwnerMemo | undefined}
    */
    get_owner_memo(idx) {
        const ret = wasm.transactionbuilder_get_owner_memo(this.ptr, idx);
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
        const ret = wasm.transferoperationbuilder_new();
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
    * @param {bigint} amount
    * @returns {TransferOperationBuilder}
    */
    add_input_with_tracing(txo_ref, asset_record, owner_memo, tracing_policies, key, amount) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(txo_ref, TxoRef);
            var ptr0 = txo_ref.__destroy_into_raw();
            _assertClass(asset_record, ClientAssetRecord);
            var ptr1 = asset_record.__destroy_into_raw();
            let ptr2 = 0;
            if (!isLikeNone(owner_memo)) {
                _assertClass(owner_memo, OwnerMemo);
                ptr2 = owner_memo.__destroy_into_raw();
            }
            _assertClass(tracing_policies, TracingPolicies);
            _assertClass(key, XfrKeyPair);
            wasm.transferoperationbuilder_add_input_with_tracing(retptr, ptr, ptr0, ptr1, ptr2, tracing_policies.ptr, key.ptr, amount);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransferOperationBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
    * @param {bigint} amount
    * @returns {TransferOperationBuilder}
    */
    add_input_no_tracing(txo_ref, asset_record, owner_memo, key, amount) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(txo_ref, TxoRef);
            var ptr0 = txo_ref.__destroy_into_raw();
            _assertClass(asset_record, ClientAssetRecord);
            let ptr1 = 0;
            if (!isLikeNone(owner_memo)) {
                _assertClass(owner_memo, OwnerMemo);
                ptr1 = owner_memo.__destroy_into_raw();
            }
            _assertClass(key, XfrKeyPair);
            wasm.transferoperationbuilder_add_input_no_tracing(retptr, ptr, ptr0, asset_record.ptr, ptr1, key.ptr, amount);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransferOperationBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
    * @param {bigint} amount
    * @param {XfrPublicKey} recipient
    * @param {TracingPolicies} tracing_policies
    * @param {string} code
    * @param {boolean} conf_amount
    * @param {boolean} conf_type
    * @returns {TransferOperationBuilder}
    */
    add_output_with_tracing(amount, recipient, tracing_policies, code, conf_amount, conf_type) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(recipient, XfrPublicKey);
            _assertClass(tracing_policies, TracingPolicies);
            const ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transferoperationbuilder_add_output_with_tracing(retptr, ptr, amount, recipient.ptr, tracing_policies.ptr, ptr0, len0, conf_amount, conf_type);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransferOperationBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
    * @param {bigint} amount
    * @param {XfrPublicKey} recipient
    * @param {string} code
    * @param {boolean} conf_amount
    * @param {boolean} conf_type
    * @returns {TransferOperationBuilder}
    */
    add_output_no_tracing(amount, recipient, code, conf_amount, conf_type) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(recipient, XfrPublicKey);
            const ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transferoperationbuilder_add_output_no_tracing(retptr, ptr, amount, recipient.ptr, ptr0, len0, conf_amount, conf_type);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransferOperationBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Wraps around TransferOperationBuilder to ensure the transfer inputs and outputs are balanced.
    * This function will add change outputs for all unspent portions of input records.
    * @throws Will throw an error if the transaction cannot be balanced.
    * @returns {TransferOperationBuilder}
    */
    balance() {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transferoperationbuilder_balance(retptr, ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransferOperationBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Wraps around TransferOperationBuilder to finalize the transaction.
    *
    * @throws Will throw an error if input and output amounts do not add up.
    * @throws Will throw an error if not all record owners have signed the transaction.
    * @returns {TransferOperationBuilder}
    */
    create() {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transferoperationbuilder_create(retptr, ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransferOperationBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(kp, XfrKeyPair);
            wasm.transferoperationbuilder_sign(retptr, ptr, kp.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransferOperationBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
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
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            var r3 = getInt32Memory0()[retptr / 4 + 3];
            var ptr0 = r0;
            var len0 = r1;
            if (r3) {
                ptr0 = 0; len0 = 0;
                throw takeObject(r2);
            }
            return getStringFromWasm0(ptr0, len0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(ptr0, len0);
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
    * @param {bigint} idx
    * @returns {TxoRef}
    */
    static relative(idx) {
        const ret = wasm.txoref_relative(idx);
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
    * @param {bigint} idx
    * @returns {TxoRef}
    */
    static absolute(idx) {
        const ret = wasm.txoref_absolute(idx);
        return TxoRef.__wrap(ret);
    }
}
/**
* The public key for the hybrid encryption scheme.
*/
export class XPublicKey {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_xpublickey_free(ptr);
    }
}
/**
* The secret key for the hybrid encryption scheme.
*/
export class XSecretKey {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_xsecretkey_free(ptr);
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
    * @returns {XfrPublicKey}
    */
    get pub_key() {
        const ret = wasm.__wbg_get_xfrkeypair_pub_key(this.ptr);
        return XfrPublicKey.__wrap(ret);
    }
    /**
    * @param {XfrPublicKey} arg0
    */
    set pub_key(arg0) {
        _assertClass(arg0, XfrPublicKey);
        var ptr0 = arg0.__destroy_into_raw();
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
/**
* The wrapped struct for `ark_bulletproofs::curve::zorro::Fq`
*/
export class ZorroFq {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_zorrofq_free(ptr);
    }
}
/**
* The wrapped struct for `ark_bulletproofs::curve::zorro::G1Projective`
*/
export class ZorroG1 {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_zorrog1_free(ptr);
    }
}
/**
* The wrapped struct for `ark_bulletproofs::curve::zorro::Fr`
*/
export class ZorroScalar {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_zorroscalar_free(ptr);
    }
}

async function load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function getImports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbindgen_object_drop_ref = function(arg0) {
        takeObject(arg0);
    };
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_json_serialize = function(arg0, arg1) {
        const obj = getObject(arg1);
        const ret = JSON.stringify(obj === undefined ? null : obj);
        const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        getInt32Memory0()[arg0 / 4 + 1] = len0;
        getInt32Memory0()[arg0 / 4 + 0] = ptr0;
    };
    imports.wbg.__wbindgen_json_parse = function(arg0, arg1) {
        const ret = JSON.parse(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_object_clone_ref = function(arg0) {
        const ret = getObject(arg0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_now_c644db5194be8437 = function(arg0) {
        const ret = getObject(arg0).now();
        return ret;
    };
    imports.wbg.__wbg_getRandomValues_37fa2ca9e4e07fab = function() { return handleError(function (arg0, arg1) {
        getObject(arg0).getRandomValues(getObject(arg1));
    }, arguments) };
    imports.wbg.__wbg_randomFillSync_dc1e9a60c158336d = function() { return handleError(function (arg0, arg1) {
        getObject(arg0).randomFillSync(takeObject(arg1));
    }, arguments) };
    imports.wbg.__wbg_crypto_c48a774b022d20ac = function(arg0) {
        const ret = getObject(arg0).crypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = getObject(arg0);
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbg_process_298734cf255a885d = function(arg0) {
        const ret = getObject(arg0).process;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_versions_e2e78e134e3e5d01 = function(arg0) {
        const ret = getObject(arg0).versions;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_node_1cd7a5d853dbea79 = function(arg0) {
        const ret = getObject(arg0).node;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'string';
        return ret;
    };
    imports.wbg.__wbg_msCrypto_bcb970640f50a1e8 = function(arg0) {
        const ret = getObject(arg0).msCrypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_require_8f08ceecec0f4fee = function() { return handleError(function () {
        const ret = module.require;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'function';
        return ret;
    };
    imports.wbg.__wbg_self_7eede1f4488bf346 = function() { return handleError(function () {
        const ret = self.self;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_crypto_c909fb428dcbddb6 = function(arg0) {
        const ret = getObject(arg0).crypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_msCrypto_511eefefbfc70ae4 = function(arg0) {
        const ret = getObject(arg0).msCrypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = getObject(arg0) === undefined;
        return ret;
    };
    imports.wbg.__wbg_static_accessor_MODULE_ef3aa2eb251158a5 = function() {
        const ret = module;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_require_900d5c3984fe7703 = function(arg0, arg1, arg2) {
        const ret = getObject(arg0).require(getStringFromWasm0(arg1, arg2));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_getRandomValues_307049345d0bd88c = function(arg0) {
        const ret = getObject(arg0).getRandomValues;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_getRandomValues_cd175915511f705e = function(arg0, arg1) {
        getObject(arg0).getRandomValues(getObject(arg1));
    };
    imports.wbg.__wbg_randomFillSync_85b3f4c52c56c313 = function(arg0, arg1, arg2) {
        getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
    };
    imports.wbg.__wbg_newnoargs_2b8b6bd7753c76ba = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_get_baf4855f9a986186 = function() { return handleError(function (arg0, arg1) {
        const ret = Reflect.get(getObject(arg0), getObject(arg1));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_call_95d1ea488d03e4e8 = function() { return handleError(function (arg0, arg1) {
        const ret = getObject(arg0).call(getObject(arg1));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_self_e7c1f827057f6584 = function() { return handleError(function () {
        const ret = self.self;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_window_a09ec664e14b1b81 = function() { return handleError(function () {
        const ret = window.window;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_globalThis_87cbb8506fecf3a9 = function() { return handleError(function () {
        const ret = globalThis.globalThis;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_global_c85a9259e621f3db = function() { return handleError(function () {
        const ret = global.global;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_call_9495de66fdbe016b = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_buffer_cf65c07de34b9a08 = function(arg0) {
        const ret = getObject(arg0).buffer;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_newwithbyteoffsetandlength_9fb2f11355ecadf5 = function(arg0, arg1, arg2) {
        const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_new_537b7341ce90bb31 = function(arg0) {
        const ret = new Uint8Array(getObject(arg0));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_set_17499e8aa4003ebd = function(arg0, arg1, arg2) {
        getObject(arg0).set(getObject(arg1), arg2 >>> 0);
    };
    imports.wbg.__wbg_length_27a2afe8ab42b09f = function(arg0) {
        const ret = getObject(arg0).length;
        return ret;
    };
    imports.wbg.__wbg_newwithlength_b56c882b57805732 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_subarray_7526649b91a252a6 = function(arg0, arg1, arg2) {
        const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_debug_string = function(arg0, arg1) {
        const ret = debugString(getObject(arg1));
        const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        getInt32Memory0()[arg0 / 4 + 1] = len0;
        getInt32Memory0()[arg0 / 4 + 0] = ptr0;
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return addHeapObject(ret);
    };

    return imports;
}

function initMemory(imports, maybe_memory) {

}

function finalizeInit(instance, module) {
    wasm = instance.exports;
    init.__wbindgen_wasm_module = module;
    cachedInt32Memory0 = null;
    cachedUint32Memory0 = null;
    cachedUint8Memory0 = null;


    return wasm;
}

function initSync(module) {
    const imports = getImports();

    initMemory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return finalizeInit(instance, module);
}

async function init(input) {
    if (typeof input === 'undefined') {
        input = new URL('wasm_bg.wasm', import.meta.url);
    }
    const imports = getImports();

    if (typeof input === 'string' || (typeof Request === 'function' && input instanceof Request) || (typeof URL === 'function' && input instanceof URL)) {
        input = fetch(input);
    }

    initMemory(imports);

    const { instance, module } = await load(await input, imports);

    return finalizeInit(instance, module);
}

export { initSync }
export default init;
