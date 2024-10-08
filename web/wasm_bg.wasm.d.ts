/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export function build_id(a: number): void;
export function random_asset_type(a: number): void;
export function hash_asset_code(a: number, b: number, c: number): void;
export function asset_type_from_jsvalue(a: number, b: number): void;
export function verify_authenticated_txn(a: number, b: number, c: number, d: number, e: number): void;
export function get_null_pk(): number;
export function __wbg_transactionbuilder_free(a: number): void;
export function __wbg_feeinputs_free(a: number): void;
export function feeinputs_new(): number;
export function feeinputs_append(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function feeinputs_append2(a: number, b: number, c: number, d: number, e: number, f: number): number;
export function transactionbuilder_add_fee_relative_auto(a: number, b: number, c: number, d: number, e: number): void;
export function transactionbuilder_get_relative_outputs(a: number, b: number): void;
export function transactionbuilder_add_fee(a: number, b: number, c: number, d: number, e: number): void;
export function transactionbuilder_check_fee(a: number): number;
export function transactionbuilder_new(a: number): number;
export function transactionbuilder_add_operation_create_asset(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number): void;
export function transactionbuilder_add_operation_create_asset_with_policy(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number): void;
export function transactionbuilder_add_basic_issue_asset(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number): void;
export function transactionbuilder_add_operation_update_memo(a: number, b: number, c: number, d: number, e: number, f: number, g: number): void;
export function transactionbuilder_add_operation_delegate(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function transactionbuilder_add_operation_undelegate(a: number, b: number, c: number): void;
export function transactionbuilder_add_operation_undelegate_partially(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function transactionbuilder_add_operation_claim(a: number, b: number, c: number, d: number, e: number): void;
export function transactionbuilder_add_operation_claim_custom(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function transactionbuilder_add_operation_convert_account(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number): void;
export function transactionbuilder_add_transfer_operation(a: number, b: number, c: number, d: number): void;
export function transactionbuilder_build(a: number, b: number): void;
export function transactionbuilder_sign(a: number, b: number, c: number): void;
export function transactionbuilder_sign_origin(a: number, b: number, c: number): void;
export function transactionbuilder_transaction(a: number, b: number): void;
export function transactionbuilder_transaction_handle(a: number, b: number): void;
export function transactionbuilder_get_owner_record(a: number, b: number): number;
export function transactionbuilder_get_owner_memo(a: number, b: number): number;
export function transfer_to_utxo_from_account(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function recover_sk_from_mnemonic(a: number, b: number, c: number, d: number, e: number): void;
export function recover_address_from_sk(a: number, b: number, c: number): void;
export function get_serialized_address(a: number, b: number, c: number): void;
export function __wbg_transferoperationbuilder_free(a: number): void;
export function transferoperationbuilder_new(): number;
export function transferoperationbuilder_add_input_with_tracing(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number): void;
export function transferoperationbuilder_add_input_no_tracing(a: number, b: number, c: number, d: number, e: number, f: number, g: number): void;
export function transferoperationbuilder_add_output_with_tracing(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number): void;
export function transferoperationbuilder_add_output_no_tracing(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number): void;
export function transferoperationbuilder_balance(a: number, b: number): void;
export function transferoperationbuilder_create(a: number, b: number): void;
export function transferoperationbuilder_sign(a: number, b: number, c: number): void;
export function transferoperationbuilder_builder(a: number, b: number): void;
export function transferoperationbuilder_transaction(a: number, b: number): void;
export function open_client_asset_record(a: number, b: number, c: number, d: number): void;
export function get_pub_key_str(a: number, b: number): void;
export function get_priv_key_str(a: number, b: number): void;
export function new_keypair(): number;
export function new_keypair_from_seed(a: number, b: number, c: number, d: number): number;
export function public_key_to_base64(a: number, b: number): void;
export function public_key_from_base64(a: number, b: number, c: number): void;
export function keypair_to_str(a: number, b: number): void;
export function keypair_from_str(a: number, b: number): number;
export function wasm_credential_issuer_key_gen(a: number): number;
export function wasm_credential_verify_commitment(a: number, b: number, c: number, d: number, e: number): void;
export function wasm_credential_open_commitment(a: number, b: number, c: number, d: number, e: number): void;
export function wasm_credential_user_key_gen(a: number): number;
export function wasm_credential_sign(a: number, b: number, c: number, d: number): void;
export function create_credential(a: number, b: number, c: number): number;
export function wasm_credential_commit(a: number, b: number, c: number, d: number): void;
export function wasm_credential_reveal(a: number, b: number, c: number, d: number): void;
export function wasm_credential_verify(a: number, b: number, c: number, d: number, e: number): void;
export function trace_assets(a: number, b: number, c: number, d: number): void;
export function public_key_to_bech32(a: number, b: number): void;
export function public_key_from_bech32(a: number, b: number, c: number): void;
export function bech32_to_base64(a: number, b: number, c: number): void;
export function base64_to_bech32(a: number, b: number, c: number): void;
export function encryption_pbkdf2_aes256gcm(a: number, b: number, c: number, d: number, e: number): void;
export function decryption_pbkdf2_aes256gcm(a: number, b: number, c: number, d: number, e: number): void;
export function create_keypair_from_secret(a: number, b: number): number;
export function get_pk_from_keypair(a: number): number;
export function generate_mnemonic_default(a: number): void;
export function generate_mnemonic_custom(a: number, b: number, c: number, d: number): void;
export function __wbg_bippath_free(a: number): void;
export function bippath_new(a: number, b: number, c: number, d: number): number;
export function restore_keypair_from_mnemonic_default(a: number, b: number, c: number): void;
export function restore_keypair_from_mnemonic_bip44(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function restore_keypair_from_mnemonic_bip49(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function fra_get_asset_code(a: number): void;
export function fra_get_minimal_fee(): number;
export function fra_get_dest_pubkey(): number;
export function get_coinbase_address(a: number): void;
export function get_delegation_min_amount(): number;
export function get_delegation_max_amount(): number;
export function get_delegation_target_address(a: number): void;
export function get_coinbase_principal_address(a: number): void;
export function __wbg_publicparams_free(a: number): void;
export function publicparams_new(): number;
export function __wbg_txoref_free(a: number): void;
export function txoref_relative(a: number): number;
export function txoref_absolute(a: number): number;
export function __wbg_authenticatedassetrecord_free(a: number): void;
export function authenticatedassetrecord_is_valid(a: number, b: number, c: number, d: number): void;
export function authenticatedassetrecord_from_json_record(a: number, b: number): void;
export function __wbg_clientassetrecord_free(a: number): void;
export function clientassetrecord_from_json(a: number, b: number): void;
export function clientassetrecord_to_json(a: number, b: number): void;
export function __wbg_assettracerkeypair_free(a: number): void;
export function assettracerkeypair_new(): number;
export function __wbg_ownermemo_free(a: number): void;
export function ownermemo_from_json(a: number, b: number): void;
export function ownermemo_clone(a: number): number;
export function __wbg_credentialuserkeypair_free(a: number): void;
export function __wbg_credentialissuerkeypair_free(a: number): void;
export function __wbg_credentialrevealsig_free(a: number): void;
export function credentialrevealsig_get_commitment(a: number): number;
export function credentialrevealsig_get_pok(a: number): number;
export function __wbg_credentialcommitmentdata_free(a: number): void;
export function credentialcommitmentdata_get_commitment(a: number): number;
export function credentialcommitmentdata_get_pok(a: number): number;
export function credentialcommitmentdata_get_commit_key(a: number): number;
export function __wbg_credentialcommitment_free(a: number): void;
export function __wbg_credentialpok_free(a: number): void;
export function __wbg_credentialcommitmentkey_free(a: number): void;
export function __wbg_assettype_free(a: number): void;
export function assettype_from_json(a: number, b: number): void;
export function assettype_get_tracing_policies(a: number): number;
export function __wbg_credential_free(a: number): void;
export function credentialissuerkeypair_get_pk(a: number): number;
export function credentialissuerkeypair_get_sk(a: number): number;
export function credentialissuerkeypair_to_json(a: number): number;
export function credentialissuerkeypair_from_json(a: number, b: number): void;
export function credentialuserkeypair_get_pk(a: number): number;
export function credentialuserkeypair_get_sk(a: number): number;
export function credentialuserkeypair_to_json(a: number): number;
export function credentialuserkeypair_from_json(a: number, b: number): void;
export function __wbg_signaturerules_free(a: number): void;
export function signaturerules_new(a: number, b: number, c: number): void;
export function __wbg_tracingpolicies_free(a: number): void;
export function __wbg_tracingpolicy_free(a: number): void;
export function tracingpolicy_new_with_tracing(a: number): number;
export function tracingpolicy_new_with_identity_tracing(a: number, b: number, c: number, d: number, e: number): void;
export function __wbg_assetrules_free(a: number): void;
export function assetrules_new(): number;
export function assetrules_add_tracing_policy(a: number, b: number): number;
export function assetrules_set_max_units(a: number, b: number): number;
export function assetrules_set_transferable(a: number, b: number): number;
export function assetrules_set_updatable(a: number, b: number): number;
export function assetrules_set_transfer_multisig_rules(a: number, b: number): number;
export function assetrules_set_decimals(a: number, b: number, c: number): void;
export function __wbg_credentialsignature_free(a: number): void;
export function __wbg_xpublickey_free(a: number): void;
export function __wbg_xsecretkey_free(a: number): void;
export function __wbg_ed25519point_free(a: number): void;
export function __wbg_blsfq_free(a: number): void;
export function __wbg_secq256k1g1_free(a: number): void;
export function __wbg_ed25519scalar_free(a: number): void;
export function __wbg_blsscalar_free(a: number): void;
export function __wbg_blsgt_free(a: number): void;
export function __wbg_zorroscalar_free(a: number): void;
export function __wbg_secq256k1scalar_free(a: number): void;
export function __wbg_zorrog1_free(a: number): void;
export function __wbg_jubjubscalar_free(a: number): void;
export function __wbg_secp256k1g1_free(a: number): void;
export function __wbg_secp256k1scalar_free(a: number): void;
export function __wbg_blsg2_free(a: number): void;
export function __wbg_zorrofq_free(a: number): void;
export function __wbg_blsg1_free(a: number): void;
export function ring_core_0_17_8_bn_mul_mont(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function __wbg_credissuersecretkey_free(a: number): void;
export function __wbg_credissuerpublickey_free(a: number): void;
export function __wbg_creduserpublickey_free(a: number): void;
export function __wbg_credusersecretkey_free(a: number): void;
export function __wbg_xfrpublickey_free(a: number): void;
export function __wbg_xfrkeypair_free(a: number): void;
export function __wbg_get_xfrkeypair_pub_key(a: number): number;
export function __wbg_set_xfrkeypair_pub_key(a: number, b: number): void;
export function __wbindgen_malloc(a: number): number;
export function __wbindgen_realloc(a: number, b: number, c: number): number;
export function __wbindgen_add_to_stack_pointer(a: number): number;
export function __wbindgen_free(a: number, b: number): void;
export function __wbindgen_exn_store(a: number): void;
