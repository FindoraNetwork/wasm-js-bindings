/* tslint:disable */
/* eslint-disable */
/**
* Returns the git commit hash and commit date of the commit this library was built against.
* @returns {string}
*/
export function build_id(): string;
/**
* Generates random Base64 encoded asset type as a Base64 string. Used in asset definitions.
* @see {@link
* module:Findora-Wasm~TransactionBuilder#add_operation_create_asset|add_operation_create_asset}
* for instructions on how to define an asset with a new
* asset type
* @returns {string}
*/
export function random_asset_type(): string;
/**
* Creates a new asset code with prefixing-hashing the original code to query the ledger.
* @param {string} asset_code_string
* @returns {string}
*/
export function hash_asset_code(asset_code_string: string): string;
/**
* Generates asset type as a Base64 string from a JSON-serialized JavaScript value.
* @param {any} val
* @returns {string}
*/
export function asset_type_from_jsvalue(val: any): string;
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
export function verify_authenticated_txn(state_commitment: string, authenticated_txn: string): boolean;
/**
* ...
* @returns {XfrPublicKey}
*/
export function get_null_pk(): XfrPublicKey;
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
export function transfer_to_utxo_from_account(recipient: XfrPublicKey, amount: bigint, sk: string, nonce: bigint): string;
/**
* Recover ecdsa private key from mnemonic.
* @param {string} phrase
* @param {string} password
* @returns {string}
*/
export function recover_sk_from_mnemonic(phrase: string, password: string): string;
/**
* Recover ethereum address from ecdsa private key, eg. 0x73c71...
* @param {string} sk
* @returns {string}
*/
export function recover_address_from_sk(sk: string): string;
/**
* Serialize ethereum address used to abci query nonce.
* @param {string} address
* @returns {string}
*/
export function get_serialized_address(address: string): string;
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
export function open_client_asset_record(record: ClientAssetRecord, owner_memo: OwnerMemo | undefined, keypair: XfrKeyPair): any;
/**
* Extracts the public key as a string from a transfer key pair.
* @param {XfrKeyPair} key_pair
* @returns {string}
*/
export function get_pub_key_str(key_pair: XfrKeyPair): string;
/**
* Extracts the private key as a string from a transfer key pair.
* @param {XfrKeyPair} key_pair
* @returns {string}
*/
export function get_priv_key_str(key_pair: XfrKeyPair): string;
/**
* Creates a new transfer key pair.
* @returns {XfrKeyPair}
*/
export function new_keypair(): XfrKeyPair;
/**
* Generates a new keypair deterministically from a seed string and an optional name.
* @param {string} seed_str
* @param {string | undefined} name
* @returns {XfrKeyPair}
*/
export function new_keypair_from_seed(seed_str: string, name?: string): XfrKeyPair;
/**
* Returns base64 encoded representation of an XfrPublicKey.
* @param {XfrPublicKey} key
* @returns {string}
*/
export function public_key_to_base64(key: XfrPublicKey): string;
/**
* Converts a base64 encoded public key string to a public key.
* @param {string} pk
* @returns {XfrPublicKey}
*/
export function public_key_from_base64(pk: string): XfrPublicKey;
/**
* Expresses a transfer key pair as a hex-encoded string.
* To decode the string, use `keypair_from_str` function.
* @param {XfrKeyPair} key_pair
* @returns {string}
*/
export function keypair_to_str(key_pair: XfrKeyPair): string;
/**
* Constructs a transfer key pair from a hex-encoded string.
* The encode a key pair, use `keypair_to_str` function.
* @param {string} str
* @returns {XfrKeyPair}
*/
export function keypair_from_str(str: string): XfrKeyPair;
/**
* Generates a new credential issuer key.
* @param {JsValue} attributes - Array of attribute types of the form `[{name: "credit_score",
* size: 3}]`. The size refers to byte-size of the credential. In this case, the "credit_score"
* attribute is represented as a 3 byte string "760". `attributes` is the list of attribute types
* that the issuer can sign off on.
* @param {any} attributes
* @returns {CredentialIssuerKeyPair}
*/
export function wasm_credential_issuer_key_gen(attributes: any): CredentialIssuerKeyPair;
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
export function wasm_credential_verify_commitment(issuer_pub_key: CredIssuerPublicKey, commitment: CredentialCommitment, pok: CredentialPoK, xfr_pk: XfrPublicKey): void;
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
export function wasm_credential_open_commitment(user_secret_key: CredUserSecretKey, credential: Credential, key: CredentialCommitmentKey, reveal_fields: any): CredentialPoK;
/**
* Generates a new credential user key.
* @param {CredIssuerPublicKey} issuer_pub_key - The credential issuer that can sign off on this
* user's attributes.
* @param {CredIssuerPublicKey} issuer_pub_key
* @returns {CredentialUserKeyPair}
*/
export function wasm_credential_user_key_gen(issuer_pub_key: CredIssuerPublicKey): CredentialUserKeyPair;
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
export function wasm_credential_sign(issuer_secret_key: CredIssuerSecretKey, user_public_key: CredUserPublicKey, attributes: any): CredentialSignature;
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
export function create_credential(issuer_public_key: CredIssuerPublicKey, signature: CredentialSignature, attributes: any): Credential;
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
export function wasm_credential_commit(user_secret_key: CredUserSecretKey, user_public_key: XfrPublicKey, credential: Credential): CredentialCommitmentData;
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
export function wasm_credential_reveal(user_sk: CredUserSecretKey, credential: Credential, reveal_fields: any): CredentialRevealSig;
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
export function wasm_credential_verify(issuer_pub_key: CredIssuerPublicKey, attributes: any, commitment: CredentialCommitment, pok: CredentialPoK): void;
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
export function trace_assets(xfr_body: any, tracer_keypair: AssetTracerKeyPair, _candidate_assets: any): any;
/**
* Returns bech32 encoded representation of an XfrPublicKey.
* @param {XfrPublicKey} key
* @returns {string}
*/
export function public_key_to_bech32(key: XfrPublicKey): string;
/**
* Converts a bech32 encoded public key string to a public key.
* @param {string} addr
* @returns {XfrPublicKey}
*/
export function public_key_from_bech32(addr: string): XfrPublicKey;
/**
* @param {string} pk
* @returns {string}
*/
export function bech32_to_base64(pk: string): string;
/**
* @param {string} pk
* @returns {string}
*/
export function base64_to_bech32(pk: string): string;
/**
* @param {string} key_pair
* @param {string} password
* @returns {Uint8Array}
*/
export function encryption_pbkdf2_aes256gcm(key_pair: string, password: string): Uint8Array;
/**
* @param {Uint8Array} enc_key_pair
* @param {string} password
* @returns {string}
*/
export function decryption_pbkdf2_aes256gcm(enc_key_pair: Uint8Array, password: string): string;
/**
* @param {string} sk_str
* @returns {XfrKeyPair | undefined}
*/
export function create_keypair_from_secret(sk_str: string): XfrKeyPair | undefined;
/**
* @param {XfrKeyPair} kp
* @returns {XfrPublicKey}
*/
export function get_pk_from_keypair(kp: XfrKeyPair): XfrPublicKey;
/**
* Randomly generate a 12words-length mnemonic.
* @returns {string}
*/
export function generate_mnemonic_default(): string;
/**
* Generate mnemonic with custom length and language.
* - @param `wordslen`: acceptable value are one of [ 12, 15, 18, 21, 24 ]
* - @param `lang`: acceptable value are one of [ "en", "zh", "zh_traditional", "fr", "it", "ko", "sp", "jp" ]
* @param {number} wordslen
* @param {string} lang
* @returns {string}
*/
export function generate_mnemonic_custom(wordslen: number, lang: string): string;
/**
* Restore the XfrKeyPair from a mnemonic with a default bip44-path,
* that is "m/44'/917'/0'/0/0" ("m/44'/coin'/account'/change/address").
* @param {string} phrase
* @returns {XfrKeyPair}
*/
export function restore_keypair_from_mnemonic_default(phrase: string): XfrKeyPair;
/**
* Restore the XfrKeyPair from a mnemonic with custom params,
* in bip44 form.
* @param {string} phrase
* @param {string} lang
* @param {BipPath} path
* @returns {XfrKeyPair}
*/
export function restore_keypair_from_mnemonic_bip44(phrase: string, lang: string, path: BipPath): XfrKeyPair;
/**
* Restore the XfrKeyPair from a mnemonic with custom params,
* in bip49 form.
* @param {string} phrase
* @param {string} lang
* @param {BipPath} path
* @returns {XfrKeyPair}
*/
export function restore_keypair_from_mnemonic_bip49(phrase: string, lang: string, path: BipPath): XfrKeyPair;
/**
* ID of FRA, in `String` format.
* @returns {string}
*/
export function fra_get_asset_code(): string;
/**
* Fee smaller than this value will be denied.
* @returns {bigint}
*/
export function fra_get_minimal_fee(): bigint;
/**
* The destination for fee to be transfered to.
* @returns {XfrPublicKey}
*/
export function fra_get_dest_pubkey(): XfrPublicKey;
/**
* The system address used to reveive delegation principals.
* @returns {string}
*/
export function get_delegation_target_address(): string;
/**
* @returns {string}
*/
export function get_coinbase_address(): string;
/**
* @returns {string}
*/
export function get_coinbase_principal_address(): string;
/**
* @returns {bigint}
*/
export function get_delegation_min_amount(): bigint;
/**
* @returns {bigint}
*/
export function get_delegation_max_amount(): bigint;
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
  free(): void;
/**
* Create a default set of asset rules. See class description for defaults.
* @returns {AssetRules}
*/
  static new(): AssetRules;
/**
* Adds an asset tracing policy.
* @param {TracingPolicy} policy - Tracing policy for the new asset.
* @param {TracingPolicy} policy
* @returns {AssetRules}
*/
  add_tracing_policy(policy: TracingPolicy): AssetRules;
/**
* Set a cap on the number of units of this asset that can be issued.
* @param {BigInt} max_units - Maximum number of units that can be issued.
* @param {bigint} max_units
* @returns {AssetRules}
*/
  set_max_units(max_units: bigint): AssetRules;
/**
* Transferability toggle. Assets that are not transferable can only be transferred by the asset
* issuer.
* @param {boolean} transferable - Boolean indicating whether asset can be transferred.
* @param {boolean} transferable
* @returns {AssetRules}
*/
  set_transferable(transferable: boolean): AssetRules;
/**
* The updatable flag determines whether the asset memo can be updated after issuance.
* @param {boolean} updatable - Boolean indicating whether asset memo can be updated.
* @see {@link module:Findora-Wasm~TransactionBuilder#add_operation_update_memo|add_operation_update_memo} for more information about how to add
* a memo update operation to a transaction.
* @param {boolean} updatable
* @returns {AssetRules}
*/
  set_updatable(updatable: boolean): AssetRules;
/**
* Co-signature rules. Assets with co-signatue rules require additional weighted signatures to
* be transferred.
* @param {SignatureRules} multisig_rules - Co-signature restrictions.
* @param {SignatureRules} multisig_rules
* @returns {AssetRules}
*/
  set_transfer_multisig_rules(multisig_rules: SignatureRules): AssetRules;
/**
* Set the decimal number of asset. Return error string if failed, otherwise return changed asset.
* #param {Number} decimals - The number of decimals used to set its user representation.
* Decimals should be 0 ~ 255.
* @param {number} decimals
* @returns {AssetRules}
*/
  set_decimals(decimals: number): AssetRules;
}
/**
* Key pair used by asset tracers to decrypt asset amounts, types, and identity
* commitments associated with traceable asset transfers.
* @see {@link module:Findora-Wasm.TracingPolicy|TracingPolicy} for information about tracing policies.
* @see {@link module:Findora-Wasm~AssetRules#add_tracing_policy|add_tracing_policy} for information about how to add a tracing policy to
* an asset definition.
*/
export class AssetTracerKeyPair {
  free(): void;
/**
* Creates a new tracer key pair.
* @returns {AssetTracerKeyPair}
*/
  static new(): AssetTracerKeyPair;
}
/**
* Object representing an asset definition. Used to fetch tracing policies and any other
* information that may be required to construct a valid transfer or issuance.
*/
export class AssetType {
  free(): void;
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
  static from_json(json: any): AssetType;
/**
* Fetch the tracing policies associated with this asset type.
* @returns {TracingPolicies}
*/
  get_tracing_policies(): TracingPolicies;
}
/**
* Object representing an authenticable asset record. Clients can validate authentication proofs
* against a ledger state commitment.
*/
export class AuthenticatedAssetRecord {
  free(): void;
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
  is_valid(state_commitment: string): boolean;
/**
* Builds an AuthenticatedAssetRecord from a JSON-encoded asset record returned from the ledger
* server.
* @param {JsValue} val - JSON-encoded asset record fetched from ledger server.
* @see {@link module:Findora-Network~Network#getUtxo|Network.getUtxo} for information about how to
* fetch an asset record from the ledger server.
* @param {any} record
* @returns {AuthenticatedAssetRecord}
*/
  static from_json_record(record: any): AuthenticatedAssetRecord;
}
/**
* The wrapped struct for `ark_bls12_381::Fq`
*/
export class BLSFq {
  free(): void;
}
/**
* The wrapped struct for ark_bls12_381::G1Projective
*/
export class BLSG1 {
  free(): void;
}
/**
* The wrapped struct for `ark_bls12_381::G2Projective`
*/
export class BLSG2 {
  free(): void;
}
/**
* The wrapped struct for [`Fp12<ark_bls12_381::Fq12Parameters>`](https://docs.rs/ark-bls12-381/0.3.0/ark_bls12_381/fq12/struct.Fq12Parameters.html),
* which is the pairing result
*/
export class BLSGt {
  free(): void;
}
/**
* The wrapped struct for `ark_bls12_381::Fr`
*/
export class BLSScalar {
  free(): void;
}
/**
* Use this struct to express a Bip44/Bip49 path.
*/
export class BipPath {
  free(): void;
/**
* @param {number} coin
* @param {number} account
* @param {number} change
* @param {number} address
* @returns {BipPath}
*/
  static new(coin: number, account: number, change: number, address: number): BipPath;
}
/**
* This object represents an asset record owned by a ledger key pair.
* @see {@link module:Findora-Wasm.open_client_asset_record|open_client_asset_record} for information about how to decrypt an encrypted asset
* record.
*/
export class ClientAssetRecord {
  free(): void;
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
  static from_json(val: any): ClientAssetRecord;
/**
* ClientAssetRecord ==> JsValue
* @returns {any}
*/
  to_json(): any;
}
/**
* Public key of a credential issuer.
*/
export class CredIssuerPublicKey {
  free(): void;
}
/**
* Secret key of a credential issuer.
*/
export class CredIssuerSecretKey {
  free(): void;
}
/**
* Public key of a credential user.
*/
export class CredUserPublicKey {
  free(): void;
}
/**
* Secret key of a credential user.
*/
export class CredUserSecretKey {
  free(): void;
}
/**
* A user credential that can be used to selectively reveal credential attributes.
* @see {@link module:Findora-Wasm.wasm_credential_commit|wasm_credential_commit} for information about how to commit to a credential.
* @see {@link module:Findora-Wasm.wasm_credential_reveal|wasm_credential_reveal} for information about how to selectively reveal credential
* attributes.
*/
export class Credential {
  free(): void;
}
/**
* Commitment to a credential record.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
*/
export class CredentialCommitment {
  free(): void;
}
/**
* Commitment to a credential record, proof that the commitment is valid, and credential key that can be used
* to open a commitment.
*/
export class CredentialCommitmentData {
  free(): void;
/**
* Returns the underlying credential commitment.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
* @returns {CredentialCommitment}
*/
  get_commitment(): CredentialCommitment;
/**
* Returns the underlying proof of knowledge that the credential is valid.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
* @returns {CredentialPoK}
*/
  get_pok(): CredentialPoK;
/**
* Returns the key used to generate the commitment.
* @see {@link module:Findora-Wasm.wasm_credential_open_commitment|wasm_credential_open_commitment} for information about how to open a
* credential commitment.
* @returns {CredentialCommitmentKey}
*/
  get_commit_key(): CredentialCommitmentKey;
}
/**
* Key used to generate a credential commitment.
* @see {@link module:Findora-Wasm.wasm_credential_open_commitment|wasm_credential_open_commitment} for information about how to
* open a credential commitment.
*/
export class CredentialCommitmentKey {
  free(): void;
}
/**
* Key pair of a credential issuer.
*/
export class CredentialIssuerKeyPair {
  free(): void;
/**
* Returns the credential issuer's public key.
* @returns {CredIssuerPublicKey}
*/
  get_pk(): CredIssuerPublicKey;
/**
* Returns the credential issuer's secret key.
* @returns {CredIssuerSecretKey}
*/
  get_sk(): CredIssuerSecretKey;
/**
* Convert the key pair to a serialized value that can be used in the browser.
* @returns {any}
*/
  to_json(): any;
/**
* Generate a key pair from a JSON-serialized JavaScript value.
* @param {any} val
* @returns {CredentialIssuerKeyPair}
*/
  static from_json(val: any): CredentialIssuerKeyPair;
}
/**
* Proof that a credential is a valid re-randomization of a credential signed by a certain asset
* issuer.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
*/
export class CredentialPoK {
  free(): void;
}
/**
* Reveal signature of a credential record.
*/
export class CredentialRevealSig {
  free(): void;
/**
* Returns the underlying credential commitment.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
* @returns {CredentialCommitment}
*/
  get_commitment(): CredentialCommitment;
/**
* Returns the underlying proof of knowledge that the credential is valid.
* @see {@link module:Findora-Wasm.wasm_credential_verify_commitment|wasm_credential_verify_commitment} for information about how to verify a
* credential commitment.
* @returns {CredentialPoK}
*/
  get_pok(): CredentialPoK;
}
/**
* Signature of a credential record.
*/
export class CredentialSignature {
  free(): void;
}
/**
* Key pair of a credential user.
*/
export class CredentialUserKeyPair {
  free(): void;
/**
* Returns the credential issuer's public key.
* @returns {CredUserPublicKey}
*/
  get_pk(): CredUserPublicKey;
/**
* Returns the credential issuer's secret key.
* @returns {CredUserSecretKey}
*/
  get_sk(): CredUserSecretKey;
/**
* Convert the key pair to a serialized value that can be used in the browser.
* @returns {any}
*/
  to_json(): any;
/**
* Generate a key pair from a JSON-serialized JavaScript value.
* @param {any} val
* @returns {CredentialUserKeyPair}
*/
  static from_json(val: any): CredentialUserKeyPair;
}
/**
* The wrapped struct for `ark_ed25519::EdwardsProjective`
*/
export class Ed25519Point {
  free(): void;
}
/**
* The wrapped struct for `ark_ed25519::Fr`
*/
export class Ed25519Scalar {
  free(): void;
}
/**
*/
export class FeeInputs {
  free(): void;
/**
* @returns {FeeInputs}
*/
  static new(): FeeInputs;
/**
* @param {bigint} am
* @param {TxoRef} tr
* @param {ClientAssetRecord} ar
* @param {OwnerMemo | undefined} om
* @param {XfrKeyPair} kp
*/
  append(am: bigint, tr: TxoRef, ar: ClientAssetRecord, om: OwnerMemo | undefined, kp: XfrKeyPair): void;
/**
* @param {bigint} am
* @param {TxoRef} tr
* @param {ClientAssetRecord} ar
* @param {OwnerMemo | undefined} om
* @param {XfrKeyPair} kp
* @returns {FeeInputs}
*/
  append2(am: bigint, tr: TxoRef, ar: ClientAssetRecord, om: OwnerMemo | undefined, kp: XfrKeyPair): FeeInputs;
}
/**
* The wrapped struct for `ark_ed_on_bls12_381::Fr`
*/
export class JubjubScalar {
  free(): void;
}
/**
* Asset owner memo. Contains information needed to decrypt an asset record.
* @see {@link module:Findora-Wasm.ClientAssetRecord|ClientAssetRecord} for more details about asset records.
*/
export class OwnerMemo {
  free(): void;
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
  static from_json(val: any): OwnerMemo;
/**
* Creates a clone of the owner memo.
* @returns {OwnerMemo}
*/
  clone(): OwnerMemo;
}
/**
* Public parameters necessary for generating asset records. Generating this is expensive and
* should be done as infrequently as possible.
* @see {@link module:Findora-Wasm~TransactionBuilder#add_basic_issue_asset|add_basic_issue_asset}
* for information using public parameters to create issuance asset records.
*/
export class PublicParams {
  free(): void;
/**
* Generates a new set of parameters.
* @returns {PublicParams}
*/
  static new(): PublicParams;
}
/**
* The wrapped struct for `ark_secp256k1::Projective`
*/
export class SECP256K1G1 {
  free(): void;
}
/**
* The wrapped struct for `ark_secp256k1::Fr`
*/
export class SECP256K1Scalar {
  free(): void;
}
/**
* The wrapped struct for `ark_secq256k1::Projective`
*/
export class SECQ256K1G1 {
  free(): void;
}
/**
* The wrapped struct for `ark_secq256k1::Fr`
*/
export class SECQ256K1Scalar {
  free(): void;
}
/**
* Stores threshold and weights for a multisignature requirement.
*/
export class SignatureRules {
  free(): void;
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
  static new(threshold: bigint, weights: any): SignatureRules;
}
/**
* A collection of tracing policies. Use this object when constructing asset transfers to generate
* the correct tracing proofs for traceable assets.
*/
export class TracingPolicies {
  free(): void;
}
/**
* Tracing policy for asset transfers. Can be configured to track credentials, the asset type and
* amount, or both.
*/
export class TracingPolicy {
  free(): void;
/**
* @param {AssetTracerKeyPair} tracing_key
* @returns {TracingPolicy}
*/
  static new_with_tracing(tracing_key: AssetTracerKeyPair): TracingPolicy;
/**
* @param {AssetTracerKeyPair} tracing_key
* @param {CredIssuerPublicKey} cred_issuer_key
* @param {any} reveal_map
* @param {boolean} tracing
* @returns {TracingPolicy}
*/
  static new_with_identity_tracing(tracing_key: AssetTracerKeyPair, cred_issuer_key: CredIssuerPublicKey, reveal_map: any, tracing: boolean): TracingPolicy;
}
/**
* Structure that allows users to construct arbitrary transactions.
*/
export class TransactionBuilder {
  free(): void;
/**
* @param am: amount to pay
* @param kp: owner's XfrKeyPair
* @param {XfrKeyPair} kp
* @param {string | undefined} memo
* @returns {TransactionBuilder}
*/
  add_fee_relative_auto(kp: XfrKeyPair, memo?: string): TransactionBuilder;
/**
* Use this func to get the necessary infomations for generating `Relative Inputs`
*
* - TxoRef::Relative("Element index of the result")
* - ClientAssetRecord::from_json("Element of the result")
* @returns {any[]}
*/
  get_relative_outputs(): any[];
/**
* As the last operation of any transaction,
* add a static fee to the transaction.
* @param {FeeInputs} inputs
* @param {string | undefined} memo
* @returns {TransactionBuilder}
*/
  add_fee(inputs: FeeInputs, memo?: string): TransactionBuilder;
/**
* A simple fee checker for mainnet v1.0.
*
* SEE [check_fee](ledger::data_model::Transaction::check_fee)
* @returns {boolean}
*/
  check_fee(): boolean;
/**
* Create a new transaction builder.
* @param {BigInt} seq_id - Unique sequence ID to prevent replay attacks.
* @param {bigint} seq_id
* @returns {TransactionBuilder}
*/
  static new(seq_id: bigint): TransactionBuilder;
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
  add_operation_create_asset(key_pair: XfrKeyPair, memo: string, token_code: string, asset_rules: AssetRules): TransactionBuilder;
/**
* @ignore
* @param {XfrKeyPair} key_pair
* @param {string} memo
* @param {string} token_code
* @param {string} _policy_choice
* @param {AssetRules} asset_rules
* @returns {TransactionBuilder}
*/
  add_operation_create_asset_with_policy(key_pair: XfrKeyPair, memo: string, token_code: string, _policy_choice: string, asset_rules: AssetRules): TransactionBuilder;
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
  add_basic_issue_asset(key_pair: XfrKeyPair, code: string, seq_num: bigint, amount: bigint, conf_amount: boolean): TransactionBuilder;
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
  add_operation_update_memo(auth_key_pair: XfrKeyPair, code: string, new_memo: string): TransactionBuilder;
/**
* @param {XfrKeyPair} keypair
* @param {bigint} amount
* @param {string} validator
* @returns {TransactionBuilder}
*/
  add_operation_delegate(keypair: XfrKeyPair, amount: bigint, validator: string): TransactionBuilder;
/**
* @param {XfrKeyPair} keypair
* @returns {TransactionBuilder}
*/
  add_operation_undelegate(keypair: XfrKeyPair): TransactionBuilder;
/**
* @param {XfrKeyPair} keypair
* @param {bigint} am
* @param {string} target_validator
* @returns {TransactionBuilder}
*/
  add_operation_undelegate_partially(keypair: XfrKeyPair, am: bigint, target_validator: string): TransactionBuilder;
/**
* @param {XfrKeyPair} keypair
* @param {Uint8Array} td_addr
* @returns {TransactionBuilder}
*/
  add_operation_claim(keypair: XfrKeyPair, td_addr: Uint8Array): TransactionBuilder;
/**
* @param {XfrKeyPair} keypair
* @param {Uint8Array} td_addr
* @param {bigint} am
* @returns {TransactionBuilder}
*/
  add_operation_claim_custom(keypair: XfrKeyPair, td_addr: Uint8Array, am: bigint): TransactionBuilder;
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
  add_operation_convert_account(keypair: XfrKeyPair, ethereum_address: string, amount: bigint, asset?: string, lowlevel_data?: string): TransactionBuilder;
/**
* Adds a serialized transfer asset operation to a transaction builder instance.
* @param {string} op - a JSON-serialized transfer operation.
* @see {@link module:Findora-Wasm~TransferOperationBuilder} for details on constructing a transfer operation.
* @throws Will throw an error if `op` fails to deserialize.
* @param {string} op
* @returns {TransactionBuilder}
*/
  add_transfer_operation(op: string): TransactionBuilder;
/**
* Do nothing, compatible with frontend
* @returns {TransactionBuilder}
*/
  build(): TransactionBuilder;
/**
* @param {XfrKeyPair} kp
* @returns {TransactionBuilder}
*/
  sign(kp: XfrKeyPair): TransactionBuilder;
/**
* @param {XfrKeyPair} kp
* @returns {TransactionBuilder}
*/
  sign_origin(kp: XfrKeyPair): TransactionBuilder;
/**
* Extracts the serialized form of a transaction.
* @returns {string}
*/
  transaction(): string;
/**
* Calculates transaction handle.
* @returns {string}
*/
  transaction_handle(): string;
/**
* Fetches a client record from a transaction.
* @param {number} idx - Record to fetch. Records are added to the transaction builder sequentially.
* @param {number} idx
* @returns {ClientAssetRecord}
*/
  get_owner_record(idx: number): ClientAssetRecord;
/**
* Fetches an owner memo from a transaction
* @param {number} idx - Owner memo to fetch. Owner memos are added to the transaction builder sequentially.
* @param {number} idx
* @returns {OwnerMemo | undefined}
*/
  get_owner_memo(idx: number): OwnerMemo | undefined;
}
/**
* Structure that enables clients to construct complex transfers.
*/
export class TransferOperationBuilder {
  free(): void;
/**
* Create a new transfer operation builder.
* @returns {TransferOperationBuilder}
*/
  static new(): TransferOperationBuilder;
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
  add_input_with_tracing(txo_ref: TxoRef, asset_record: ClientAssetRecord, owner_memo: OwnerMemo | undefined, tracing_policies: TracingPolicies, key: XfrKeyPair, amount: bigint): TransferOperationBuilder;
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
  add_input_no_tracing(txo_ref: TxoRef, asset_record: ClientAssetRecord, owner_memo: OwnerMemo | undefined, key: XfrKeyPair, amount: bigint): TransferOperationBuilder;
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
* @param {string | undefined} memo
* @returns {TransferOperationBuilder}
*/
  add_output_with_tracing(amount: bigint, recipient: XfrPublicKey, tracing_policies: TracingPolicies, code: string, conf_amount: boolean, conf_type: boolean, memo?: string): TransferOperationBuilder;
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
* @param {string | undefined} memo
* @returns {TransferOperationBuilder}
*/
  add_output_no_tracing(amount: bigint, recipient: XfrPublicKey, code: string, conf_amount: boolean, conf_type: boolean, memo?: string): TransferOperationBuilder;
/**
* Wraps around TransferOperationBuilder to ensure the transfer inputs and outputs are balanced.
* This function will add change outputs for all unspent portions of input records.
* @throws Will throw an error if the transaction cannot be balanced.
* @returns {TransferOperationBuilder}
*/
  balance(): TransferOperationBuilder;
/**
* Wraps around TransferOperationBuilder to finalize the transaction.
*
* @throws Will throw an error if input and output amounts do not add up.
* @throws Will throw an error if not all record owners have signed the transaction.
* @returns {TransferOperationBuilder}
*/
  create(): TransferOperationBuilder;
/**
* Wraps around TransferOperationBuilder to add a signature to the operation.
*
* All input owners must sign.
*
* @param {XfrKeyPair} kp - key pair of one of the input owners.
* @param {XfrKeyPair} kp
* @returns {TransferOperationBuilder}
*/
  sign(kp: XfrKeyPair): TransferOperationBuilder;
/**
* @returns {string}
*/
  builder(): string;
/**
* Wraps around TransferOperationBuilder to extract an operation expression as JSON.
* @returns {string}
*/
  transaction(): string;
}
/**
* Indicates whether the TXO ref is an absolute or relative value.
*/
export class TxoRef {
  free(): void;
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
  static relative(idx: bigint): TxoRef;
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
  static absolute(idx: bigint): TxoRef;
}
/**
* The public key for the hybrid encryption scheme.
*/
export class XPublicKey {
  free(): void;
}
/**
* The secret key for the hybrid encryption scheme.
*/
export class XSecretKey {
  free(): void;
}
/**
*/
export class XfrKeyPair {
  free(): void;
/**
*/
  pub_key: XfrPublicKey;
}
/**
*/
export class XfrPublicKey {
  free(): void;
}
/**
* The wrapped struct for `ark_bulletproofs::curve::zorro::Fq`
*/
export class ZorroFq {
  free(): void;
}
/**
* The wrapped struct for `ark_bulletproofs::curve::zorro::G1Projective`
*/
export class ZorroG1 {
  free(): void;
}
/**
* The wrapped struct for `ark_bulletproofs::curve::zorro::Fr`
*/
export class ZorroScalar {
  free(): void;
}
