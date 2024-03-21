// Call 'wasm-pack build --target nodejs' to build from this directory for this command to work
const wasm = require('./wasm.js');
const axios = require('axios');

let kp_sender = wasm.restore_keypair_from_mnemonic_default("zoo nerve assault talk depend approve mercy surge bicycle ridge dismiss satoshi boring opera next fat cinnamon valley office actor above spray alcohol giant");
//console.log("sender:", wasm.public_key_to_base64(kp_sender.pub_key));
let kp_reveicer = wasm.new_keypair();
//console.log("reveicer:",wasm.keypair_to_str(kp_reveicer));

let utxo = JSON.parse('{"id":null,"record":{"amount":{"NonConfidential":"47489623119996"},"asset_type":{"NonConfidential":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},"public_key":"HZnxwPI5PD_xpQX1NqKTHXqPdHXVXtGe7yQ0JI3MVTs="}}');
let fee_pub_key = wasm.public_key_from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
let transfer_op = wasm.TransferOperationBuilder.new()
    .add_input_no_tracing(wasm.TxoRef.absolute(57314n), wasm.ClientAssetRecord.from_json(utxo), null, kp_sender, 1000n)
    .add_output_no_tracing(10000n, fee_pub_key, wasm.fra_get_asset_code(), false, false, null)
    //.add_output_no_tracing(1n, kp_reveicer.pub_key, wasm.fra_get_asset_code(), false, false, '{"p":"brc-20","op":"deploy","tick":"ordi","max":"21000000","lim":"1000"}')
    //.add_output_no_tracing(1n, kp_reveicer.pub_key, wasm.fra_get_asset_code(), false, false, '{"p":"brc-20","op":"mint","tick":"ordi","amt":"1000"}')
    .add_output_no_tracing(1n, kp_reveicer.pub_key, wasm.fra_get_asset_code(), false, false, '{"p":"brc-20","op":"transfer","tick":"ordi","amt":"1000"}')
    .add_output_no_tracing(47489623109995n, kp_sender.pub_key, wasm.fra_get_asset_code(), false, false, null)
    .create()
    .sign(kp_sender)
    .transaction();

let seq_id = 19121n;
let asset_rules = wasm.AssetRules.new();
let tx =wasm.TransactionBuilder.new(seq_id).add_transfer_operation(transfer_op)
        .sign(kp_sender)
        .transaction();
//console.log(tx)

const stringToHex = (str) => {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    const charCode = str.charCodeAt(i);
    const hexValue = charCode.toString(16);

    // Pad with zeros to ensure two-digit representation
    hex += hexValue.padStart(2, '0');
  }
  return hex;
};

console.log(stringToHex(tx));
