/* tslint:disable */
/* eslint-disable */
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
}
/**
* Object representing an asset definition. Used to fetch tracing policies and any other
* information that may be required to construct a valid transfer or issuance.
*/
export class AssetType {
  free(): void;
}
/**
* Object representing an authenticable asset record. Clients can validate authentication proofs
* against a ledger state commitment.
*/
export class AuthenticatedAssetRecord {
  free(): void;
}
/**
* Use this struct to express a Bip44/Bip49 path.
*/
export class BipPath {
  free(): void;
}
/**
* This object represents an asset record owned by a ledger key pair.
* @see {@link module:Findora-Wasm.open_client_asset_record|open_client_asset_record} for information about how to decrypt an encrypted asset
* record.
*/
export class ClientAssetRecord {
  free(): void;
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
}
/**
*/
export class FeeInputs {
  free(): void;
}
/**
* Asset owner memo. Contains information needed to decrypt an asset record.
* @see {@link module:Findora-Wasm.ClientAssetRecord|ClientAssetRecord} for more details about asset records.
*/
export class OwnerMemo {
  free(): void;
}
/**
* Public parameters necessary for generating asset records. Generating this is expensive and
* should be done as infrequently as possible.
* @see {@link module:Findora-Wasm~TransactionBuilder#add_basic_issue_asset|add_basic_issue_asset}
* for information using public parameters to create issuance asset records.
*/
export class PublicParams {
  free(): void;
}
/**
* Stores threshold and weights for a multisignature requirement.
*/
export class SignatureRules {
  free(): void;
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
}
/**
* Structure that allows users to construct arbitrary transactions.
*/
export class TransactionBuilder {
  free(): void;
}
/**
* Structure that enables clients to construct complex transfers.
*/
export class TransferOperationBuilder {
  free(): void;
}
/**
* Indicates whether the TXO ref is an absolute or relative value.
*/
export class TxoRef {
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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_publicparams_free: (a: number) => void;
  readonly __wbg_txoref_free: (a: number) => void;
  readonly __wbg_authenticatedassetrecord_free: (a: number) => void;
  readonly __wbg_clientassetrecord_free: (a: number) => void;
  readonly __wbg_assettracerkeypair_free: (a: number) => void;
  readonly __wbg_ownermemo_free: (a: number) => void;
  readonly __wbg_credentialuserkeypair_free: (a: number) => void;
  readonly __wbg_credentialissuerkeypair_free: (a: number) => void;
  readonly __wbg_credentialrevealsig_free: (a: number) => void;
  readonly __wbg_credentialcommitmentdata_free: (a: number) => void;
  readonly __wbg_credentialcommitment_free: (a: number) => void;
  readonly __wbg_credentialpok_free: (a: number) => void;
  readonly __wbg_credentialcommitmentkey_free: (a: number) => void;
  readonly __wbg_assettype_free: (a: number) => void;
  readonly __wbg_credential_free: (a: number) => void;
  readonly __wbg_signaturerules_free: (a: number) => void;
  readonly __wbg_tracingpolicies_free: (a: number) => void;
  readonly __wbg_tracingpolicy_free: (a: number) => void;
  readonly __wbg_assetrules_free: (a: number) => void;
  readonly __wbg_credentialsignature_free: (a: number) => void;
  readonly __wbg_transactionbuilder_free: (a: number) => void;
  readonly __wbg_feeinputs_free: (a: number) => void;
  readonly __wbg_transferoperationbuilder_free: (a: number) => void;
  readonly __wbg_bippath_free: (a: number) => void;
  readonly __wbg_credissuersecretkey_free: (a: number) => void;
  readonly __wbg_credissuerpublickey_free: (a: number) => void;
  readonly __wbg_creduserpublickey_free: (a: number) => void;
  readonly __wbg_credusersecretkey_free: (a: number) => void;
  readonly __wbg_xfrpublickey_free: (a: number) => void;
  readonly __wbg_xfrkeypair_free: (a: number) => void;
  readonly __wbg_get_xfrkeypair_pub_key: (a: number) => number;
  readonly __wbg_set_xfrkeypair_pub_key: (a: number, b: number) => void;
}

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
