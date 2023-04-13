"use strict";

const CSL = require("@emurgo/cardano-serialization-lib-browser");

// Pass in a function and its list of arguments, that is expected to fail on evaluation, wraps in Either
function errorableToPurs(f, ...vars) {
  return left => right => {
    try {
      return right(f(...vars));
    }
    catch (err) {
      if(typeof err === "string") return left(err)
      else return left(err.message);
    }
  }
}

// funs

exports.minFee = tx => linear_fee => CSL.min_fee(tx, linear_fee);
exports.calculateExUnitsCeilCost = ex_units => ex_unit_prices => CSL.calculate_ex_units_ceil_cost(ex_units, ex_unit_prices);
exports.minScriptFee = tx => ex_unit_prices => CSL.min_script_fee(tx, ex_unit_prices);
exports.encryptWithPassword = password => salt => nonce => data => CSL.encrypt_with_password(password, salt, nonce, data);
exports.decryptWithPassword = password => data => CSL.decrypt_with_password(password, data);
exports.makeDaedalusBootstrapWitness = tx_body_hash => addr => key => CSL.make_daedalus_bootstrap_witness(tx_body_hash, addr, key);
exports.makeIcarusBootstrapWitness = tx_body_hash => addr => key => CSL.make_icarus_bootstrap_witness(tx_body_hash, addr, key);
exports.makeVkeyWitness = tx_body_hash => sk => CSL.make_vkey_witness(tx_body_hash, sk);
exports.hashAuxiliaryData = auxiliary_data => CSL.hash_auxiliary_data(auxiliary_data);
exports.hashTx = tx_body => CSL.hash_transaction(tx_body);
exports.hashPlutusData = plutus_data => CSL.hash_plutus_data(plutus_data);
exports.hashScriptData = redeemers => cost_models => datums => CSL.hash_script_data(redeemers, cost_models, datums);
exports.getImplicitIn = txbody => pool_deposit => key_deposit => CSL.get_implicit_input(txbody, pool_deposit, key_deposit);
exports.getDeposit = txbody => pool_deposit => key_deposit => CSL.get_deposit(txbody, pool_deposit, key_deposit);
exports.minAdaForOut = output => data_cost => CSL.min_ada_for_output(output, data_cost);
exports.minAdaRequired = assets => has_data_hash => coins_per_utxo_word => CSL.min_ada_required(assets, has_data_hash, coins_per_utxo_word);
exports.encodeJsonStrToNativeScript = json => self_xpub => schema => CSL.encode_json_str_to_native_script(json, self_xpub, schema);
exports.encodeJsonStrToPlutusDatum = json => schema => CSL.encode_json_str_to_plutus_datum(json, schema);
exports.decodePlutusDatumToJsonStr = datum => schema => CSL.decode_plutus_datum_to_json_str(datum, schema);
exports.encodeArbitraryBytesAsMetadatum = bytes => CSL.encode_arbitrary_bytes_as_metadatum(bytes);
exports.decodeArbitraryBytesFromMetadatum = metadata => CSL.decode_arbitrary_bytes_from_metadatum(metadata);
exports.encodeJsonStrToMetadatum = json => schema => CSL.encode_json_str_to_metadatum(json, schema);
exports.decodeMetadatumToJsonStr = metadatum => schema => CSL.decode_metadatum_to_json_str(metadatum, schema);

// ----------------------------------------------------------------------
// types

// Address
exports.address_free = self => () => self.free();
exports.address_fromBytes = data => errorableToPurs(CSL.Address.from_bytes, data);
exports.address_toJson = self => self.to_json();
exports.address_toJsValue = self => self.to_js_value();
exports.address_fromJson = json => errorableToPurs(CSL.Address.from_json, json);
exports.address_toHex = self => self.to_hex();
exports.address_fromHex = hex_str => errorableToPurs(CSL.Address.from_hex, hex_str);
exports.address_toBytes = self => self.to_bytes();
exports.address_toBech32 = self => prefix => self.to_bech32(prefix);
exports.address_fromBech32 = bech_str => errorableToPurs(CSL.Address.from_bech32, bech_str);
exports.address_networkId = self => self.network_id();

// AssetName
exports.assetName_free = self => () => self.free();
exports.assetName_toBytes = self => self.to_bytes();
exports.assetName_fromBytes = bytes => errorableToPurs(CSL.AssetName.from_bytes, bytes);
exports.assetName_toHex = self => self.to_hex();
exports.assetName_fromHex = hex_str => errorableToPurs(CSL.AssetName.from_hex, hex_str);
exports.assetName_toJson = self => self.to_json();
exports.assetName_toJsValue = self => self.to_js_value();
exports.assetName_fromJson = json => errorableToPurs(CSL.AssetName.from_json, json);
exports.assetName_new = name => CSL.AssetName.new(name);
exports.assetName_name = self => self.name();

// AssetNames
exports.assetNames_free = self => () => self.free();
exports.assetNames_toBytes = self => self.to_bytes();
exports.assetNames_fromBytes = bytes => errorableToPurs(CSL.AssetNames.from_bytes, bytes);
exports.assetNames_toHex = self => self.to_hex();
exports.assetNames_fromHex = hex_str => errorableToPurs(CSL.AssetNames.from_hex, hex_str);
exports.assetNames_toJson = self => self.to_json();
exports.assetNames_toJsValue = self => self.to_js_value();
exports.assetNames_fromJson = json => errorableToPurs(CSL.AssetNames.from_json, json);
exports.assetNames_new = () => CSL.AssetNames.new();
exports.assetNames_len = self => () => self.len();
exports.assetNames_get = self => index => () => self.get(index);
exports.assetNames_add = self => elem => () => self.add(elem);

// Assets
exports.assets_free = self => () => self.free();
exports.assets_toBytes = self => self.to_bytes();
exports.assets_fromBytes = bytes => errorableToPurs(CSL.Assets.from_bytes, bytes);
exports.assets_toHex = self => self.to_hex();
exports.assets_fromHex = hex_str => errorableToPurs(CSL.Assets.from_hex, hex_str);
exports.assets_toJson = self => self.to_json();
exports.assets_toJsValue = self => self.to_js_value();
exports.assets_fromJson = json => errorableToPurs(CSL.Assets.from_json, json);
exports.assets_new = () => CSL.Assets.new();
exports.assets_len = self => () => self.len();
exports.assets_insert = self => key => value => () => self.insert(key, value);
exports.assets_get = self => key => () => self.get(key);
exports.assets_keys = self => () => self.keys();

// AuxiliaryData
exports.auxiliaryData_free = self => () => self.free();
exports.auxiliaryData_toBytes = self => self.to_bytes();
exports.auxiliaryData_fromBytes = bytes => errorableToPurs(CSL.AuxiliaryData.from_bytes, bytes);
exports.auxiliaryData_toHex = self => self.to_hex();
exports.auxiliaryData_fromHex = hex_str => errorableToPurs(CSL.AuxiliaryData.from_hex, hex_str);
exports.auxiliaryData_toJson = self => self.to_json();
exports.auxiliaryData_toJsValue = self => self.to_js_value();
exports.auxiliaryData_fromJson = json => errorableToPurs(CSL.AuxiliaryData.from_json, json);
exports.auxiliaryData_new = () => CSL.AuxiliaryData.new();
exports.auxiliaryData_metadata = self => self.metadata();
exports.auxiliaryData_setMetadata = self => metadata => () => self.set_metadata(metadata);
exports.auxiliaryData_nativeScripts = self => () => self.native_scripts();
exports.auxiliaryData_setNativeScripts = self => native_scripts => () => self.set_native_scripts(native_scripts);
exports.auxiliaryData_plutusScripts = self => () => self.plutus_scripts();
exports.auxiliaryData_setPlutusScripts = self => plutus_scripts => () => self.set_plutus_scripts(plutus_scripts);

// AuxiliaryDataHash
exports.auxiliaryDataHash_free = self => () => self.free();
exports.auxiliaryDataHash_fromBytes = bytes => errorableToPurs(CSL.AuxiliaryDataHash.from_bytes, bytes);
exports.auxiliaryDataHash_toBytes = self => self.to_bytes();
exports.auxiliaryDataHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.auxiliaryDataHash_fromBech32 = bech_str => errorableToPurs(CSL.AuxiliaryDataHash.from_bech32, bech_str);
exports.auxiliaryDataHash_toHex = self => self.to_hex();
exports.auxiliaryDataHash_fromHex = hex => errorableToPurs(CSL.AuxiliaryDataHash.from_hex, hex);

// AuxiliaryDataSet
exports.auxiliaryDataSet_free = self => () => self.free();
exports.auxiliaryDataSet_new = () => CSL.AuxiliaryDataSet.new();
exports.auxiliaryDataSet_len = self => self.len();
exports.auxiliaryDataSet_insert = self => tx_index => data => () => self.insert(tx_index, data);
exports.auxiliaryDataSet_get = self => tx_index => () => self.get(tx_index);
exports.auxiliaryDataSet_indices = self => () => self.indices();

// BaseAddress
exports.baseAddress_free = self => () => self.free();
exports.baseAddress_new = network => payment => stake => CSL.BaseAddress.new(network, payment, stake);
exports.baseAddress_paymentCred = self => self.payment_cred();
exports.baseAddress_stakeCred = self => self.stake_cred();
exports.baseAddress_toAddress = self => self.to_address();
exports.baseAddress_fromAddress = addr => CSL.BaseAddress.from_address(addr);

// BigInt
exports.bigInt_free = self => () => self.free();
exports.bigInt_toBytes = self => self.to_bytes();
exports.bigInt_fromBytes = bytes => errorableToPurs(CSL.BigInt.from_bytes, bytes);
exports.bigInt_toHex = self => self.to_hex();
exports.bigInt_fromHex = hex_str => errorableToPurs(CSL.BigInt.from_hex, hex_str);
exports.bigInt_toJson = self => self.to_json();
exports.bigInt_toJsValue = self => self.to_js_value();
exports.bigInt_fromJson = json => errorableToPurs(CSL.BigInt.from_json, json);
exports.bigInt_isZero = self => self.is_zero();
exports.bigInt_asU64 = self => self.as_u64();
exports.bigInt_asInt = self => self.as_int();
exports.bigInt_fromStr = text => errorableToPurs(CSL.BigInt.from_str, text);
exports.bigInt_toStr = self => self.to_str();
exports.bigInt_add = self => other => self.add(other);
exports.bigInt_mul = self => other => self.mul(other);
exports.bigInt_one = CSL.BigInt.one();
exports.bigInt_increment = self => self.increment();
exports.bigInt_divCeil = self => other => self.div_ceil(other);

// BigNum
exports.bigNum_free = self => () => self.free();
exports.bigNum_toBytes = self => self.to_bytes();
exports.bigNum_fromBytes = bytes => errorableToPurs(CSL.BigNum.from_bytes, bytes);
exports.bigNum_toHex = self => self.to_hex();
exports.bigNum_fromHex = hex_str => errorableToPurs(CSL.BigNum.from_hex, hex_str);
exports.bigNum_toJson = self => self.to_json();
exports.bigNum_toJsValue = self => self.to_js_value();
exports.bigNum_fromJson = json => errorableToPurs(CSL.BigNum.from_json, json);
exports.bigNum_fromStr = string => errorableToPurs(CSL.BigNum.from_str, string);
exports.bigNum_toStr = self => self.to_str();
exports.bigNum_zero = CSL.BigNum.zero();
exports.bigNum_one = CSL.BigNum.one();
exports.bigNum_isZero = self => self.is_zero();
exports.bigNum_divFloor = self => other => self.div_floor(other);
exports.bigNum_checkedMul = self => other => self.checked_mul(other);
exports.bigNum_checkedAdd = self => other => self.checked_add(other);
exports.bigNum_checkedSub = self => other => self.checked_sub(other);
exports.bigNum_clampedSub = self => other => self.clamped_sub(other);
exports.bigNum_compare = self => rhs_value => self.compare(rhs_value);
exports.bigNum_lessThan = self => rhs_value => self.less_than(rhs_value);
exports.bigNum_max = a => b => CSL.BigNum.max(a, b);

// Bip32PrivateKey
exports.bip32PrivateKey_free = self => () => self.free();
exports.bip32PrivateKey_derive = self => index => self.derive(index);
exports.bip32PrivateKey_from128Xprv = bytes => CSL.Bip32PrivateKey.from_128_xprv(bytes);
exports.bip32PrivateKey_to128Xprv = self => self.to_128_xprv();
exports.bip32PrivateKey_generateEd25519Bip32 = CSL.Bip32PrivateKey.generate_ed25519_bip32();
exports.bip32PrivateKey_toRawKey = self => self.to_raw_key();
exports.bip32PrivateKey_toPublic = self => self.to_public();
exports.bip32PrivateKey_fromBytes = bytes => errorableToPurs(CSL.Bip32PrivateKey.from_bytes, bytes);
exports.bip32PrivateKey_asBytes = self => self.as_bytes();
exports.bip32PrivateKey_fromBech32 = bech32_str => errorableToPurs(CSL.Bip32PrivateKey.from_bech32, bech32_str);
exports.bip32PrivateKey_toBech32 = self => self.to_bech32();
exports.bip32PrivateKey_fromBip39Entropy = entropy => password => CSL.Bip32PrivateKey.from_bip39_entropy(entropy, password);
exports.bip32PrivateKey_chaincode = self => self.chaincode();
exports.bip32PrivateKey_toHex = self => self.to_hex();
exports.bip32PrivateKey_fromHex = hex_str => errorableToPurs(CSL.Bip32PrivateKey.from_hex, hex_str);

// Bip32PublicKey
exports.bip32PublicKey_free = self => () => self.free();
exports.bip32PublicKey_derive = self => index => self.derive(index);
exports.bip32PublicKey_toRawKey = self => self.to_raw_key();
exports.bip32PublicKey_fromBytes = bytes => errorableToPurs(CSL.Bip32PublicKey.from_bytes, bytes);
exports.bip32PublicKey_asBytes = self => self.as_bytes();
exports.bip32PublicKey_fromBech32 = bech32_str => errorableToPurs(CSL.Bip32PublicKey.from_bech32, bech32_str);
exports.bip32PublicKey_toBech32 = self => self.to_bech32();
exports.bip32PublicKey_chaincode = self => self.chaincode();
exports.bip32PublicKey_toHex = self => self.to_hex();
exports.bip32PublicKey_fromHex = hex_str => errorableToPurs(CSL.Bip32PublicKey.from_hex, hex_str);

// Block
exports.block_free = self => () => self.free();
exports.block_toBytes = self => self.to_bytes();
exports.block_fromBytes = bytes => errorableToPurs(CSL.Block.from_bytes, bytes);
exports.block_toHex = self => self.to_hex();
exports.block_fromHex = hex_str => errorableToPurs(CSL.Block.from_hex, hex_str);
exports.block_toJson = self => self.to_json();
exports.block_toJsValue = self => self.to_js_value();
exports.block_fromJson = json => errorableToPurs(CSL.Block.from_json, json);
exports.block_header = self => self.header();
exports.block_txBodies = self => self.transaction_bodies();
exports.block_txWitnessSets = self => self.transaction_witness_sets();
exports.block_auxiliaryDataSet = self => self.auxiliary_data_set();
exports.block_invalidTxs = self => self.invalid_transactions();
exports.block_new = header => transaction_bodies => transaction_witness_sets => auxiliary_data_set => invalid_transactions => CSL.Block.new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions);

// BlockHash
exports.blockHash_free = self => () => self.free();
exports.blockHash_fromBytes = bytes => errorableToPurs(CSL.BlockHash.from_bytes, bytes);
exports.blockHash_toBytes = self => self.to_bytes();
exports.blockHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.blockHash_fromBech32 = bech_str => errorableToPurs(CSL.BlockHash.from_bech32, bech_str);
exports.blockHash_toHex = self => self.to_hex();
exports.blockHash_fromHex = hex => errorableToPurs(CSL.BlockHash.from_hex, hex);

// BootstrapWitness
exports.bootstrapWitness_free = self => () => self.free();
exports.bootstrapWitness_toBytes = self => self.to_bytes();
exports.bootstrapWitness_fromBytes = bytes => errorableToPurs(CSL.BootstrapWitness.from_bytes, bytes);
exports.bootstrapWitness_toHex = self => self.to_hex();
exports.bootstrapWitness_fromHex = hex_str => errorableToPurs(CSL.BootstrapWitness.from_hex, hex_str);
exports.bootstrapWitness_toJson = self => self.to_json();
exports.bootstrapWitness_toJsValue = self => self.to_js_value();
exports.bootstrapWitness_fromJson = json => errorableToPurs(CSL.BootstrapWitness.from_json, json);
exports.bootstrapWitness_vkey = self => self.vkey();
exports.bootstrapWitness_signature = self => self.signature();
exports.bootstrapWitness_chainCode = self => self.chain_code();
exports.bootstrapWitness_attributes = self => self.attributes();
exports.bootstrapWitness_new = vkey => signature => chain_code => attributes => CSL.BootstrapWitness.new(vkey, signature, chain_code, attributes);

// BootstrapWitnesses
exports.bootstrapWitnesses_free = self => () => self.free();
exports.bootstrapWitnesses_new = () => CSL.BootstrapWitnesses.new();
exports.bootstrapWitnesses_len = self => () => self.len();
exports.bootstrapWitnesses_get = self => index => () => self.get(index);
exports.bootstrapWitnesses_add = self => elem => () => self.add(elem);

// ByronAddress
exports.byronAddress_free = self => () => self.free();
exports.byronAddress_toBase58 = self => self.to_base58();
exports.byronAddress_toBytes = self => self.to_bytes();
exports.byronAddress_fromBytes = bytes => errorableToPurs(CSL.ByronAddress.from_bytes, bytes);
exports.byronAddress_byronProtocolMagic = self => self.byron_protocol_magic();
exports.byronAddress_attributes = self => self.attributes();
exports.byronAddress_networkId = self => self.network_id();
exports.byronAddress_fromBase58 = s => CSL.ByronAddress.from_base58(s);
exports.byronAddress_icarusFromKey = key => protocol_magic => CSL.ByronAddress.icarus_from_key(key, protocol_magic);
exports.byronAddress_isValid = s => CSL.ByronAddress.is_valid(s);
exports.byronAddress_toAddress = self => self.to_address();
exports.byronAddress_fromAddress = addr => CSL.ByronAddress.from_address(addr);

// Certificate
exports.certificate_free = self => () => self.free();
exports.certificate_toBytes = self => self.to_bytes();
exports.certificate_fromBytes = bytes => errorableToPurs(CSL.Certificate.from_bytes, bytes);
exports.certificate_toHex = self => self.to_hex();
exports.certificate_fromHex = hex_str => errorableToPurs(CSL.Certificate.from_hex, hex_str);
exports.certificate_toJson = self => self.to_json();
exports.certificate_toJsValue = self => self.to_js_value();
exports.certificate_fromJson = json => errorableToPurs(CSL.Certificate.from_json, json);
exports.certificate_newStakeRegistration = stake_registration => CSL.Certificate.new_stake_registration(stake_registration);
exports.certificate_newStakeDeregistration = stake_deregistration => CSL.Certificate.new_stake_deregistration(stake_deregistration);
exports.certificate_newStakeDelegation = stake_delegation => CSL.Certificate.new_stake_delegation(stake_delegation);
exports.certificate_newPoolRegistration = pool_registration => CSL.Certificate.new_pool_registration(pool_registration);
exports.certificate_newPoolRetirement = pool_retirement => CSL.Certificate.new_pool_retirement(pool_retirement);
exports.certificate_newGenesisKeyDelegation = genesis_key_delegation => CSL.Certificate.new_genesis_key_delegation(genesis_key_delegation);
exports.certificate_newMoveInstantaneousRewardsCert = move_instantaneous_rewards_cert => CSL.Certificate.new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert);
exports.certificate_kind = self => self.kind();
exports.certificate_asStakeRegistration = self => self.as_stake_registration();
exports.certificate_asStakeDeregistration = self => self.as_stake_deregistration();
exports.certificate_asStakeDelegation = self => self.as_stake_delegation();
exports.certificate_asPoolRegistration = self => self.as_pool_registration();
exports.certificate_asPoolRetirement = self => self.as_pool_retirement();
exports.certificate_asGenesisKeyDelegation = self => self.as_genesis_key_delegation();
exports.certificate_asMoveInstantaneousRewardsCert = self => self.as_move_instantaneous_rewards_cert();

// Certificates
exports.certificates_free = self => () => self.free();
exports.certificates_toBytes = self => self.to_bytes();
exports.certificates_fromBytes = bytes => errorableToPurs(CSL.Certificates.from_bytes, bytes);
exports.certificates_toHex = self => self.to_hex();
exports.certificates_fromHex = hex_str => errorableToPurs(CSL.Certificates.from_hex, hex_str);
exports.certificates_toJson = self => self.to_json();
exports.certificates_toJsValue = self => self.to_js_value();
exports.certificates_fromJson = json => errorableToPurs(CSL.Certificates.from_json, json);
exports.certificates_new = () => CSL.Certificates.new();
exports.certificates_len = self => () => self.len();
exports.certificates_get = self => index => () => self.get(index);
exports.certificates_add = self => elem => () => self.add(elem);

// ConstrPlutusData
exports.constrPlutusData_free = self => () => self.free();
exports.constrPlutusData_toBytes = self => self.to_bytes();
exports.constrPlutusData_fromBytes = bytes => errorableToPurs(CSL.ConstrPlutusData.from_bytes, bytes);
exports.constrPlutusData_toHex = self => self.to_hex();
exports.constrPlutusData_fromHex = hex_str => errorableToPurs(CSL.ConstrPlutusData.from_hex, hex_str);
exports.constrPlutusData_toJson = self => self.to_json();
exports.constrPlutusData_toJsValue = self => self.to_js_value();
exports.constrPlutusData_fromJson = json => errorableToPurs(CSL.ConstrPlutusData.from_json, json);
exports.constrPlutusData_alternative = self => self.alternative();
exports.constrPlutusData_data = self => self.data();
exports.constrPlutusData_new = alternative => data => CSL.ConstrPlutusData.new(alternative, data);

// CostModel
exports.costModel_free = self => () => self.free();
exports.costModel_toBytes = self => self.to_bytes();
exports.costModel_fromBytes = bytes => errorableToPurs(CSL.CostModel.from_bytes, bytes);
exports.costModel_toHex = self => self.to_hex();
exports.costModel_fromHex = hex_str => errorableToPurs(CSL.CostModel.from_hex, hex_str);
exports.costModel_toJson = self => self.to_json();
exports.costModel_toJsValue = self => self.to_js_value();
exports.costModel_fromJson = json => errorableToPurs(CSL.CostModel.from_json, json);
exports.costModel_new = () => CSL.CostModel.new();
exports.costModel_set = self => operation => cost => () => self.set(operation, cost);
exports.costModel_get = self => operation => () => self.get(operation);
exports.costModel_len = self => () => self.len();

// Costmdls
exports.costmdls_free = self => () => self.free();
exports.costmdls_toBytes = self => self.to_bytes();
exports.costmdls_fromBytes = bytes => errorableToPurs(CSL.Costmdls.from_bytes, bytes);
exports.costmdls_toHex = self => self.to_hex();
exports.costmdls_fromHex = hex_str => errorableToPurs(CSL.Costmdls.from_hex, hex_str);
exports.costmdls_toJson = self => self.to_json();
exports.costmdls_toJsValue = self => self.to_js_value();
exports.costmdls_fromJson = json => errorableToPurs(CSL.Costmdls.from_json, json);
exports.costmdls_new = () => CSL.Costmdls.new();
exports.costmdls_len = self => () => self.len();
exports.costmdls_insert = self => key => value => () => self.insert(key, value);
exports.costmdls_get = self => key => () => self.get(key);
exports.costmdls_keys = self => () => self.keys();
exports.costmdls_retainLanguageVersions = self => languages => self.retain_language_versions(languages);

// DNSRecordAorAAAA
exports.dnsRecordAorAAAA_free = self => () => self.free();
exports.dnsRecordAorAAAA_toBytes = self => self.to_bytes();
exports.dnsRecordAorAAAA_fromBytes = bytes => errorableToPurs(CSL.DNSRecordAorAAAA.from_bytes, bytes);
exports.dnsRecordAorAAAA_toHex = self => self.to_hex();
exports.dnsRecordAorAAAA_fromHex = hex_str => errorableToPurs(CSL.DNSRecordAorAAAA.from_hex, hex_str);
exports.dnsRecordAorAAAA_toJson = self => self.to_json();
exports.dnsRecordAorAAAA_toJsValue = self => self.to_js_value();
exports.dnsRecordAorAAAA_fromJson = json => errorableToPurs(CSL.DNSRecordAorAAAA.from_json, json);
exports.dnsRecordAorAAAA_new = dns_name => CSL.DNSRecordAorAAAA.new(dns_name);
exports.dnsRecordAorAAAA_record = self => self.record();

// DNSRecordSRV
exports.dnsRecordSRV_free = self => () => self.free();
exports.dnsRecordSRV_toBytes = self => self.to_bytes();
exports.dnsRecordSRV_fromBytes = bytes => errorableToPurs(CSL.DNSRecordSRV.from_bytes, bytes);
exports.dnsRecordSRV_toHex = self => self.to_hex();
exports.dnsRecordSRV_fromHex = hex_str => errorableToPurs(CSL.DNSRecordSRV.from_hex, hex_str);
exports.dnsRecordSRV_toJson = self => self.to_json();
exports.dnsRecordSRV_toJsValue = self => self.to_js_value();
exports.dnsRecordSRV_fromJson = json => errorableToPurs(CSL.DNSRecordSRV.from_json, json);
exports.dnsRecordSRV_new = dns_name => CSL.DNSRecordSRV.new(dns_name);
exports.dnsRecordSRV_record = self => self.record();

// DataCost
exports.dataCost_free = self => () => self.free();
exports.dataCost_newCoinsPerWord = coins_per_word => CSL.DataCost.new_coins_per_word(coins_per_word);
exports.dataCost_newCoinsPerByte = coins_per_byte => CSL.DataCost.new_coins_per_byte(coins_per_byte);
exports.dataCost_coinsPerByte = self => self.coins_per_byte();

// DataHash
exports.dataHash_free = self => () => self.free();
exports.dataHash_fromBytes = bytes => errorableToPurs(CSL.DataHash.from_bytes, bytes);
exports.dataHash_toBytes = self => self.to_bytes();
exports.dataHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.dataHash_fromBech32 = bech_str => errorableToPurs(CSL.DataHash.from_bech32, bech_str);
exports.dataHash_toHex = self => self.to_hex();
exports.dataHash_fromHex = hex => errorableToPurs(CSL.DataHash.from_hex, hex);

// DatumSource
exports.datumSource_free = self => () => self.free();
exports.datumSource_new = datum => CSL.DatumSource.new(datum);
exports.datumSource_newRefIn = input => CSL.DatumSource.new_ref_input(input);

// Ed25519KeyHash
exports.ed25519KeyHash_free = self => () => self.free();
exports.ed25519KeyHash_fromBytes = bytes => errorableToPurs(CSL.Ed25519KeyHash.from_bytes, bytes);
exports.ed25519KeyHash_toBytes = self => self.to_bytes();
exports.ed25519KeyHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.ed25519KeyHash_fromBech32 = bech_str => errorableToPurs(CSL.Ed25519KeyHash.from_bech32, bech_str);
exports.ed25519KeyHash_toHex = self => self.to_hex();
exports.ed25519KeyHash_fromHex = hex => errorableToPurs(CSL.Ed25519KeyHash.from_hex, hex);

// Ed25519KeyHashes
exports.ed25519KeyHashes_free = self => () => self.free();
exports.ed25519KeyHashes_toBytes = self => self.to_bytes();
exports.ed25519KeyHashes_fromBytes = bytes => errorableToPurs(CSL.Ed25519KeyHashes.from_bytes, bytes);
exports.ed25519KeyHashes_toHex = self => self.to_hex();
exports.ed25519KeyHashes_fromHex = hex_str => errorableToPurs(CSL.Ed25519KeyHashes.from_hex, hex_str);
exports.ed25519KeyHashes_toJson = self => self.to_json();
exports.ed25519KeyHashes_toJsValue = self => self.to_js_value();
exports.ed25519KeyHashes_fromJson = json => errorableToPurs(CSL.Ed25519KeyHashes.from_json, json);
exports.ed25519KeyHashes_new = CSL.Ed25519KeyHashes.new();
exports.ed25519KeyHashes_len = self => self.len();
exports.ed25519KeyHashes_get = self => index => self.get(index);
exports.ed25519KeyHashes_add = self => elem => () => self.add(elem);
exports.ed25519KeyHashes_toOption = self => self.to_option();

// Ed25519Signature
exports.ed25519Signature_free = self => () => self.free();
exports.ed25519Signature_toBytes = self => self.to_bytes();
exports.ed25519Signature_toBech32 = self => self.to_bech32();
exports.ed25519Signature_toHex = self => self.to_hex();
exports.ed25519Signature_fromBech32 = bech32_str => errorableToPurs(CSL.Ed25519Signature.from_bech32, bech32_str);
exports.ed25519Signature_fromHex = input => errorableToPurs(CSL.Ed25519Signature.from_hex, input);
exports.ed25519Signature_fromBytes = bytes => errorableToPurs(CSL.Ed25519Signature.from_bytes, bytes);

// EnterpriseAddress
exports.enterpriseAddress_free = self => () => self.free();
exports.enterpriseAddress_new = network => payment => CSL.EnterpriseAddress.new(network, payment);
exports.enterpriseAddress_paymentCred = self => self.payment_cred();
exports.enterpriseAddress_toAddress = self => self.to_address();
exports.enterpriseAddress_fromAddress = addr => CSL.EnterpriseAddress.from_address(addr);

// ExUnitPrices
exports.exUnitPrices_free = self => () => self.free();
exports.exUnitPrices_toBytes = self => self.to_bytes();
exports.exUnitPrices_fromBytes = bytes => errorableToPurs(CSL.ExUnitPrices.from_bytes, bytes);
exports.exUnitPrices_toHex = self => self.to_hex();
exports.exUnitPrices_fromHex = hex_str => errorableToPurs(CSL.ExUnitPrices.from_hex, hex_str);
exports.exUnitPrices_toJson = self => self.to_json();
exports.exUnitPrices_toJsValue = self => self.to_js_value();
exports.exUnitPrices_fromJson = json => errorableToPurs(CSL.ExUnitPrices.from_json, json);
exports.exUnitPrices_memPrice = self => self.mem_price();
exports.exUnitPrices_stepPrice = self => self.step_price();
exports.exUnitPrices_new = mem_price => step_price => CSL.ExUnitPrices.new(mem_price, step_price);

// ExUnits
exports.exUnits_free = self => () => self.free();
exports.exUnits_toBytes = self => self.to_bytes();
exports.exUnits_fromBytes = bytes => errorableToPurs(CSL.ExUnits.from_bytes, bytes);
exports.exUnits_toHex = self => self.to_hex();
exports.exUnits_fromHex = hex_str => errorableToPurs(CSL.ExUnits.from_hex, hex_str);
exports.exUnits_toJson = self => self.to_json();
exports.exUnits_toJsValue = self => self.to_js_value();
exports.exUnits_fromJson = json => errorableToPurs(CSL.ExUnits.from_json, json);
exports.exUnits_mem = self => self.mem();
exports.exUnits_steps = self => self.steps();
exports.exUnits_new = mem => steps => CSL.ExUnits.new(mem, steps);

// GeneralTransactionMetadata
exports.generalTxMetadata_free = self => () => self.free();
exports.generalTxMetadata_toBytes = self => self.to_bytes();
exports.generalTxMetadata_fromBytes = bytes => errorableToPurs(CSL.GeneralTransactionMetadata.from_bytes, bytes);
exports.generalTxMetadata_toHex = self => self.to_hex();
exports.generalTxMetadata_fromHex = hex_str => errorableToPurs(CSL.GeneralTransactionMetadata.from_hex, hex_str);
exports.generalTxMetadata_toJson = self => self.to_json();
exports.generalTxMetadata_toJsValue = self => self.to_js_value();
exports.generalTxMetadata_fromJson = json => errorableToPurs(CSL.GeneralTransactionMetadata.from_json, json);
exports.generalTxMetadata_new = () => CSL.GeneralTransactionMetadata.new();
exports.generalTxMetadata_len = self => () => self.len();
exports.generalTxMetadata_insert = self => key => value => () => self.insert(key, value);
exports.generalTxMetadata_get = self => key => () => self.get(key);
exports.generalTxMetadata_keys = self => () => self.keys();

// GenesisDelegateHash
exports.genesisDelegateHash_free = self => () => self.free();
exports.genesisDelegateHash_fromBytes = bytes => errorableToPurs(CSL.GenesisDelegateHash.from_bytes, bytes);
exports.genesisDelegateHash_toBytes = self => self.to_bytes();
exports.genesisDelegateHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.genesisDelegateHash_fromBech32 = bech_str => errorableToPurs(CSL.GenesisDelegateHash.from_bech32, bech_str);
exports.genesisDelegateHash_toHex = self => self.to_hex();
exports.genesisDelegateHash_fromHex = hex => errorableToPurs(CSL.GenesisDelegateHash.from_hex, hex);

// GenesisHash
exports.genesisHash_free = self => () => self.free();
exports.genesisHash_fromBytes = bytes => errorableToPurs(CSL.GenesisHash.from_bytes, bytes);
exports.genesisHash_toBytes = self => self.to_bytes();
exports.genesisHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.genesisHash_fromBech32 = bech_str => errorableToPurs(CSL.GenesisHash.from_bech32, bech_str);
exports.genesisHash_toHex = self => self.to_hex();
exports.genesisHash_fromHex = hex => errorableToPurs(CSL.GenesisHash.from_hex, hex);

// GenesisHashes
exports.genesisHashes_free = self => () => self.free();
exports.genesisHashes_toBytes = self => self.to_bytes();
exports.genesisHashes_fromBytes = bytes => errorableToPurs(CSL.GenesisHashes.from_bytes, bytes);
exports.genesisHashes_toHex = self => self.to_hex();
exports.genesisHashes_fromHex = hex_str => errorableToPurs(CSL.GenesisHashes.from_hex, hex_str);
exports.genesisHashes_toJson = self => self.to_json();
exports.genesisHashes_toJsValue = self => self.to_js_value();
exports.genesisHashes_fromJson = json => errorableToPurs(CSL.GenesisHashes.from_json, json);
exports.genesisHashes_new = () => CSL.GenesisHashes.new();
exports.genesisHashes_len = self => () => self.len();
exports.genesisHashes_get = self => index => () => self.get(index);
exports.genesisHashes_add = self => elem => () => self.add(elem);

// GenesisKeyDelegation
exports.genesisKeyDelegation_free = self => () => self.free();
exports.genesisKeyDelegation_toBytes = self => self.to_bytes();
exports.genesisKeyDelegation_fromBytes = bytes => errorableToPurs(CSL.GenesisKeyDelegation.from_bytes, bytes);
exports.genesisKeyDelegation_toHex = self => self.to_hex();
exports.genesisKeyDelegation_fromHex = hex_str => errorableToPurs(CSL.GenesisKeyDelegation.from_hex, hex_str);
exports.genesisKeyDelegation_toJson = self => self.to_json();
exports.genesisKeyDelegation_toJsValue = self => self.to_js_value();
exports.genesisKeyDelegation_fromJson = json => errorableToPurs(CSL.GenesisKeyDelegation.from_json, json);
exports.genesisKeyDelegation_genesishash = self => self.genesishash();
exports.genesisKeyDelegation_genesisDelegateHash = self => self.genesis_delegate_hash();
exports.genesisKeyDelegation_vrfKeyhash = self => self.vrf_keyhash();
exports.genesisKeyDelegation_new = genesishash => genesis_delegate_hash => vrf_keyhash => CSL.GenesisKeyDelegation.new(genesishash, genesis_delegate_hash, vrf_keyhash);

// Header
exports.header_free = self => () => self.free();
exports.header_toBytes = self => self.to_bytes();
exports.header_fromBytes = bytes => errorableToPurs(CSL.Header.from_bytes, bytes);
exports.header_toHex = self => self.to_hex();
exports.header_fromHex = hex_str => errorableToPurs(CSL.Header.from_hex, hex_str);
exports.header_toJson = self => self.to_json();
exports.header_toJsValue = self => self.to_js_value();
exports.header_fromJson = json => errorableToPurs(CSL.Header.from_json, json);
exports.header_headerBody = self => self.header_body();
exports.header_bodySignature = self => self.body_signature();
exports.header_new = header_body => body_signature => CSL.Header.new(header_body, body_signature);

// HeaderBody
exports.headerBody_free = self => () => self.free();
exports.headerBody_toBytes = self => self.to_bytes();
exports.headerBody_fromBytes = bytes => errorableToPurs(CSL.HeaderBody.from_bytes, bytes);
exports.headerBody_toHex = self => self.to_hex();
exports.headerBody_fromHex = hex_str => errorableToPurs(CSL.HeaderBody.from_hex, hex_str);
exports.headerBody_toJson = self => self.to_json();
exports.headerBody_toJsValue = self => self.to_js_value();
exports.headerBody_fromJson = json => errorableToPurs(CSL.HeaderBody.from_json, json);
exports.headerBody_blockNumber = self => self.block_number();
exports.headerBody_slot = self => self.slot();
exports.headerBody_slotBignum = self => self.slot_bignum();
exports.headerBody_prevHash = self => self.prev_hash();
exports.headerBody_issuerVkey = self => self.issuer_vkey();
exports.headerBody_vrfVkey = self => self.vrf_vkey();
exports.headerBody_hasNonceAndLeaderVrf = self => self.has_nonce_and_leader_vrf();
exports.headerBody_nonceVrfOrNothing = self => self.nonce_vrf_or_nothing();
exports.headerBody_leaderVrfOrNothing = self => self.leader_vrf_or_nothing();
exports.headerBody_hasVrfResult = self => self.has_vrf_result();
exports.headerBody_vrfResultOrNothing = self => self.vrf_result_or_nothing();
exports.headerBody_blockBodySize = self => self.block_body_size();
exports.headerBody_blockBodyHash = self => self.block_body_hash();
exports.headerBody_operationalCert = self => self.operational_cert();
exports.headerBody_protocolVersion = self => self.protocol_version();
exports.headerBody_new = block_number => slot => prev_hash => issuer_vkey => vrf_vkey => vrf_result => block_body_size => block_body_hash => operational_cert => protocol_version => CSL.HeaderBody.new(block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
exports.headerBody_newHeaderbody = block_number => slot => prev_hash => issuer_vkey => vrf_vkey => vrf_result => block_body_size => block_body_hash => operational_cert => protocol_version => CSL.HeaderBody.new_headerbody(block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);

// Int
exports.int_free = self => () => self.free();
exports.int_toBytes = self => self.to_bytes();
exports.int_fromBytes = bytes => errorableToPurs(CSL.Int.from_bytes, bytes);
exports.int_toHex = self => self.to_hex();
exports.int_fromHex = hex_str => errorableToPurs(CSL.Int.from_hex, hex_str);
exports.int_toJson = self => self.to_json();
exports.int_toJsValue = self => self.to_js_value();
exports.int_fromJson = json => errorableToPurs(CSL.Int.from_json, json);
exports.int_new = x => CSL.Int.new(x);
exports.int_newNegative = x => CSL.Int.new_negative(x);
exports.int_newI32 = x => CSL.Int.new_i32(x);
exports.int_isPositive = self => self.is_positive();
exports.int_asPositive = self => self.as_positive();
exports.int_asNegative = self => self.as_negative();
exports.int_asI32 = self => self.as_i32();
exports.int_asI32OrNothing = self => self.as_i32_or_nothing();
exports.int_asI32OrFail = self => self.as_i32_or_fail();
exports.int_toStr = self => self.to_str();
exports.int_fromStr = string => errorableToPurs(CSL.Int.from_str, string);

// Ipv4
exports.ipv4_free = self => () => self.free();
exports.ipv4_toBytes = self => self.to_bytes();
exports.ipv4_fromBytes = bytes => errorableToPurs(CSL.Ipv4.from_bytes, bytes);
exports.ipv4_toHex = self => self.to_hex();
exports.ipv4_fromHex = hex_str => errorableToPurs(CSL.Ipv4.from_hex, hex_str);
exports.ipv4_toJson = self => self.to_json();
exports.ipv4_toJsValue = self => self.to_js_value();
exports.ipv4_fromJson = json => errorableToPurs(CSL.Ipv4.from_json, json);
exports.ipv4_new = data => CSL.Ipv4.new(data);
exports.ipv4_ip = self => self.ip();

// Ipv6
exports.ipv6_free = self => () => self.free();
exports.ipv6_toBytes = self => self.to_bytes();
exports.ipv6_fromBytes = bytes => errorableToPurs(CSL.Ipv6.from_bytes, bytes);
exports.ipv6_toHex = self => self.to_hex();
exports.ipv6_fromHex = hex_str => errorableToPurs(CSL.Ipv6.from_hex, hex_str);
exports.ipv6_toJson = self => self.to_json();
exports.ipv6_toJsValue = self => self.to_js_value();
exports.ipv6_fromJson = json => errorableToPurs(CSL.Ipv6.from_json, json);
exports.ipv6_new = data => CSL.Ipv6.new(data);
exports.ipv6_ip = self => self.ip();

// KESSignature
exports.kesSignature_free = self => () => self.free();
exports.kesSignature_toBytes = self => self.to_bytes();
exports.kesSignature_fromBytes = bytes => errorableToPurs(CSL.KESSignature.from_bytes, bytes);

// KESVKey
exports.kesvKey_free = self => () => self.free();
exports.kesvKey_fromBytes = bytes => errorableToPurs(CSL.KESVKey.from_bytes, bytes);
exports.kesvKey_toBytes = self => self.to_bytes();
exports.kesvKey_toBech32 = self => prefix => self.to_bech32(prefix);
exports.kesvKey_fromBech32 = bech_str => errorableToPurs(CSL.KESVKey.from_bech32, bech_str);
exports.kesvKey_toHex = self => self.to_hex();
exports.kesvKey_fromHex = hex => errorableToPurs(CSL.KESVKey.from_hex, hex);

// Language
exports.language_free = self => () => self.free();
exports.language_toBytes = self => self.to_bytes();
exports.language_fromBytes = bytes => errorableToPurs(CSL.Language.from_bytes, bytes);
exports.language_toHex = self => self.to_hex();
exports.language_fromHex = hex_str => errorableToPurs(CSL.Language.from_hex, hex_str);
exports.language_toJson = self => self.to_json();
exports.language_toJsValue = self => self.to_js_value();
exports.language_fromJson = json => errorableToPurs(CSL.Language.from_json, json);
exports.language_newPlutusV1 = CSL.Language.new_plutus_v1();
exports.language_newPlutusV2 = CSL.Language.new_plutus_v2();
exports.language_kind = self => self.kind();

// Languages
exports.languages_free = self => () => self.free();
exports.languages_new = () => CSL.Languages.new();
exports.languages_len = self => () => self.len();
exports.languages_get = self => index => () => self.get(index);
exports.languages_add = self => elem => () => self.add(elem);

// LegacyDaedalusPrivateKey
exports.legacyDaedalusPrivateKey_free = self => () => self.free();
exports.legacyDaedalusPrivateKey_fromBytes = bytes => errorableToPurs(CSL.LegacyDaedalusPrivateKey.from_bytes, bytes);
exports.legacyDaedalusPrivateKey_asBytes = self => self.as_bytes();
exports.legacyDaedalusPrivateKey_chaincode = self => self.chaincode();

// LinearFee
exports.linearFee_free = self => () => self.free();
exports.linearFee_constant = self => self.constant();
exports.linearFee_coefficient = self => self.coefficient();
exports.linearFee_new = coefficient => constant => CSL.LinearFee.new(coefficient, constant);

// MIRToStakeCredentials
exports.mirToStakeCredentials_free = self => () => self.free();
exports.mirToStakeCredentials_toBytes = self => self.to_bytes();
exports.mirToStakeCredentials_fromBytes = bytes => errorableToPurs(CSL.MIRToStakeCredentials.from_bytes, bytes);
exports.mirToStakeCredentials_toHex = self => self.to_hex();
exports.mirToStakeCredentials_fromHex = hex_str => errorableToPurs(CSL.MIRToStakeCredentials.from_hex, hex_str);
exports.mirToStakeCredentials_toJson = self => self.to_json();
exports.mirToStakeCredentials_toJsValue = self => self.to_js_value();
exports.mirToStakeCredentials_fromJson = json => errorableToPurs(CSL.MIRToStakeCredentials.from_json, json);
exports.mirToStakeCredentials_new = () => CSL.MIRToStakeCredentials.new();
exports.mirToStakeCredentials_len = self => () => self.len();
exports.mirToStakeCredentials_insert = self => cred => delta => () => self.insert(cred, delta);
exports.mirToStakeCredentials_get = self => cred => () => self.get(cred);
exports.mirToStakeCredentials_keys = self => () => self.keys();

// MetadataList
exports.metadataList_free = self => () => self.free();
exports.metadataList_toBytes = self => self.to_bytes();
exports.metadataList_fromBytes = bytes => errorableToPurs(CSL.MetadataList.from_bytes, bytes);
exports.metadataList_toHex = self => self.to_hex();
exports.metadataList_fromHex = hex_str => errorableToPurs(CSL.MetadataList.from_hex, hex_str);
exports.metadataList_new = () => CSL.MetadataList.new();
exports.metadataList_len = self => () => self.len();
exports.metadataList_get = self => index => () => self.get(index);
exports.metadataList_add = self => elem => () => self.add(elem);

// MetadataMap
exports.metadataMap_free = self => () => self.free();
exports.metadataMap_toBytes = self => self.to_bytes();
exports.metadataMap_fromBytes = bytes => errorableToPurs(CSL.MetadataMap.from_bytes, bytes);
exports.metadataMap_toHex = self => self.to_hex();
exports.metadataMap_fromHex = hex_str => errorableToPurs(CSL.MetadataMap.from_hex, hex_str);
exports.metadataMap_new = () => CSL.MetadataMap.new();
exports.metadataMap_len = self => self.len();
exports.metadataMap_insert = self => key => value => () => self.insert(key, value);
exports.metadataMap_insertStr = self => key => value => () => self.insert_str(key, value);
exports.metadataMap_insertI32 = self => key => value => () => self.insert_i32(key, value);
exports.metadataMap_get = self => key => () => self.get(key);
exports.metadataMap_getStr = self => key => () => self.get_str(key);
exports.metadataMap_getI32 = self => key => () => self.get_i32(key);
exports.metadataMap_has = self => key => () => self.has(key);
exports.metadataMap_keys = self => () => self.keys();

// Mint
exports.mint_free = self => () => self.free();
exports.mint_toBytes = self => self.to_bytes();
exports.mint_fromBytes = bytes => errorableToPurs(CSL.Mint.from_bytes, bytes);
exports.mint_toHex = self => self.to_hex();
exports.mint_fromHex = hex_str => errorableToPurs(CSL.Mint.from_hex, hex_str);
exports.mint_toJson = self => self.to_json();
exports.mint_toJsValue = self => self.to_js_value();
exports.mint_fromJson = json => errorableToPurs(CSL.Mint.from_json, json);
exports.mint_new = () => CSL.Mint.new();
exports.mint_newFromEntry = key => value => () => CSL.Mint.new_from_entry(key, value);
exports.mint_len = self => () => self.len();
exports.mint_insert = self => key => value => () => self.insert(key, value);
exports.mint_get = self => key => () => self.get(key);
exports.mint_keys = self => () => self.keys();
exports.mint_asPositiveMultiasset = self => () => self.as_positive_multiasset();
exports.mint_asNegativeMultiasset = self => () => self.as_negative_multiasset();

// MintAssets
exports.mintAssets_free = self => () => self.free();
exports.mintAssets_new = () => CSL.MintAssets.new();
exports.mintAssets_newFromEntry = key => value => CSL.MintAssets.new_from_entry(key, value);
exports.mintAssets_len = self => () => self.len();
exports.mintAssets_insert = self => key => value => () => self.insert(key, value);
exports.mintAssets_get = self => key => () => self.get(key);
exports.mintAssets_keys = self => () => self.keys();

// MoveInstantaneousReward
exports.moveInstantaneousReward_free = self => () => self.free();
exports.moveInstantaneousReward_toBytes = self => self.to_bytes();
exports.moveInstantaneousReward_fromBytes = bytes => errorableToPurs(CSL.MoveInstantaneousReward.from_bytes, bytes);
exports.moveInstantaneousReward_toHex = self => self.to_hex();
exports.moveInstantaneousReward_fromHex = hex_str => errorableToPurs(CSL.MoveInstantaneousReward.from_hex, hex_str);
exports.moveInstantaneousReward_toJson = self => self.to_json();
exports.moveInstantaneousReward_toJsValue = self => self.to_js_value();
exports.moveInstantaneousReward_fromJson = json => errorableToPurs(CSL.MoveInstantaneousReward.from_json, json);
exports.moveInstantaneousReward_newToOtherPot = pot => amount => CSL.MoveInstantaneousReward.new_to_other_pot(pot, amount);
exports.moveInstantaneousReward_newToStakeCreds = pot => amounts => CSL.MoveInstantaneousReward.new_to_stake_creds(pot, amounts);
exports.moveInstantaneousReward_pot = self => self.pot();
exports.moveInstantaneousReward_kind = self => self.kind();
exports.moveInstantaneousReward_asToOtherPot = self => self.as_to_other_pot();
exports.moveInstantaneousReward_asToStakeCreds = self => self.as_to_stake_creds();

// MoveInstantaneousRewardsCert
exports.moveInstantaneousRewardsCert_free = self => () => self.free();
exports.moveInstantaneousRewardsCert_toBytes = self => self.to_bytes();
exports.moveInstantaneousRewardsCert_fromBytes = bytes => errorableToPurs(CSL.MoveInstantaneousRewardsCert.from_bytes, bytes);
exports.moveInstantaneousRewardsCert_toHex = self => self.to_hex();
exports.moveInstantaneousRewardsCert_fromHex = hex_str => errorableToPurs(CSL.MoveInstantaneousRewardsCert.from_hex, hex_str);
exports.moveInstantaneousRewardsCert_toJson = self => self.to_json();
exports.moveInstantaneousRewardsCert_toJsValue = self => self.to_js_value();
exports.moveInstantaneousRewardsCert_fromJson = json => errorableToPurs(CSL.MoveInstantaneousRewardsCert.from_json, json);
exports.moveInstantaneousRewardsCert_moveInstantaneousReward = self => self.move_instantaneous_reward();
exports.moveInstantaneousRewardsCert_new = move_instantaneous_reward => CSL.MoveInstantaneousRewardsCert.new(move_instantaneous_reward);

// MultiAsset
exports.multiAsset_free = self => () => self.free();
exports.multiAsset_toBytes = self => self.to_bytes();
exports.multiAsset_fromBytes = bytes => errorableToPurs(CSL.MultiAsset.from_bytes, bytes);
exports.multiAsset_toHex = self => self.to_hex();
exports.multiAsset_fromHex = hex_str => errorableToPurs(CSL.MultiAsset.from_hex, hex_str);
exports.multiAsset_toJson = self => self.to_json();
exports.multiAsset_toJsValue = self => self.to_js_value();
exports.multiAsset_fromJson = json => errorableToPurs(CSL.MultiAsset.from_json, json);
exports.multiAsset_new = () => CSL.MultiAsset.new();
exports.multiAsset_len = self => () => self.len();
exports.multiAsset_insert = self => policy_id => assets => self.insert(policy_id, assets);
exports.multiAsset_get = self => policy_id => () => self.get(policy_id);
exports.multiAsset_setAsset = self => policy_id => asset_name => value => () => self.set_asset(policy_id, asset_name, value);
exports.multiAsset_getAsset = self => policy_id => asset_name => () => self.get_asset(policy_id, asset_name);
exports.multiAsset_keys = self => () => self.keys();
exports.multiAsset_sub = self => rhs_ma => () => self.sub(rhs_ma);

// MultiHostName
exports.multiHostName_free = self => () => self.free();
exports.multiHostName_toBytes = self => self.to_bytes();
exports.multiHostName_fromBytes = bytes => errorableToPurs(CSL.MultiHostName.from_bytes, bytes);
exports.multiHostName_toHex = self => self.to_hex();
exports.multiHostName_fromHex = hex_str => errorableToPurs(CSL.MultiHostName.from_hex, hex_str);
exports.multiHostName_toJson = self => self.to_json();
exports.multiHostName_toJsValue = self => self.to_js_value();
exports.multiHostName_fromJson = json => errorableToPurs(CSL.MultiHostName.from_json, json);
exports.multiHostName_dnsName = self => self.dns_name();
exports.multiHostName_new = dns_name => CSL.MultiHostName.new(dns_name);

// NativeScript
exports.nativeScript_free = self => () => self.free();
exports.nativeScript_toBytes = self => self.to_bytes();
exports.nativeScript_fromBytes = bytes => errorableToPurs(CSL.NativeScript.from_bytes, bytes);
exports.nativeScript_toHex = self => self.to_hex();
exports.nativeScript_fromHex = hex_str => errorableToPurs(CSL.NativeScript.from_hex, hex_str);
exports.nativeScript_toJson = self => self.to_json();
exports.nativeScript_toJsValue = self => self.to_js_value();
exports.nativeScript_fromJson = json => errorableToPurs(CSL.NativeScript.from_json, json);
exports.nativeScript_hash = self => self.hash();
exports.nativeScript_newScriptPubkey = script_pubkey => CSL.NativeScript.new_script_pubkey(script_pubkey);
exports.nativeScript_newScriptAll = script_all => CSL.NativeScript.new_script_all(script_all);
exports.nativeScript_newScriptAny = script_any => CSL.NativeScript.new_script_any(script_any);
exports.nativeScript_newScriptNOfK = script_n_of_k => CSL.NativeScript.new_script_n_of_k(script_n_of_k);
exports.nativeScript_newTimelockStart = timelock_start => CSL.NativeScript.new_timelock_start(timelock_start);
exports.nativeScript_newTimelockExpiry = timelock_expiry => CSL.NativeScript.new_timelock_expiry(timelock_expiry);
exports.nativeScript_kind = self => self.kind();
exports.nativeScript_asScriptPubkey = self => self.as_script_pubkey();
exports.nativeScript_asScriptAll = self => self.as_script_all();
exports.nativeScript_asScriptAny = self => self.as_script_any();
exports.nativeScript_asScriptNOfK = self => self.as_script_n_of_k();
exports.nativeScript_asTimelockStart = self => self.as_timelock_start();
exports.nativeScript_asTimelockExpiry = self => self.as_timelock_expiry();
exports.nativeScript_getRequiredSigners = self => self.get_required_signers();

// NativeScripts
exports.nativeScripts_free = self => () => self.free();
exports.nativeScripts_new = () => CSL.NativeScripts.new();
exports.nativeScripts_len = self => () => self.len();
exports.nativeScripts_get = self => index => () => self.get(index);
exports.nativeScripts_add = self => elem => () => self.add(elem);

// NetworkId
exports.networkId_free = self => () => self.free();
exports.networkId_toBytes = self => self.to_bytes();
exports.networkId_fromBytes = bytes => errorableToPurs(CSL.NetworkId.from_bytes, bytes);
exports.networkId_toHex = self => self.to_hex();
exports.networkId_fromHex = hex_str => errorableToPurs(CSL.NetworkId.from_hex, hex_str);
exports.networkId_toJson = self => self.to_json();
exports.networkId_toJsValue = self => self.to_js_value();
exports.networkId_fromJson = json => errorableToPurs(CSL.NetworkId.from_json, json);
exports.networkId_testnet = CSL.NetworkId.testnet();
exports.networkId_mainnet = CSL.NetworkId.mainnet();
exports.networkId_kind = self => self.kind();

// NetworkInfo
exports.networkInfo_free = self => () => self.free();
exports.networkInfo_new = network_id => protocol_magic => CSL.NetworkInfo.new(network_id, protocol_magic);
exports.networkInfo_networkId = self => self.network_id();
exports.networkInfo_protocolMagic = self => self.protocol_magic();
exports.networkInfo_testnet = CSL.NetworkInfo.testnet();
exports.networkInfo_mainnet = CSL.NetworkInfo.mainnet();

// Nonce
exports.nonce_free = self => () => self.free();
exports.nonce_toBytes = self => self.to_bytes();
exports.nonce_fromBytes = bytes => errorableToPurs(CSL.Nonce.from_bytes, bytes);
exports.nonce_toHex = self => self.to_hex();
exports.nonce_fromHex = hex_str => errorableToPurs(CSL.Nonce.from_hex, hex_str);
exports.nonce_toJson = self => self.to_json();
exports.nonce_toJsValue = self => self.to_js_value();
exports.nonce_fromJson = json => errorableToPurs(CSL.Nonce.from_json, json);
exports.nonce_newIdentity = CSL.Nonce.new_identity();
exports.nonce_newFromHash = hash => CSL.Nonce.new_from_hash(hash);
exports.nonce_getHash = self => self.get_hash();

// OperationalCert
exports.operationalCert_free = self => () => self.free();
exports.operationalCert_toBytes = self => self.to_bytes();
exports.operationalCert_fromBytes = bytes => errorableToPurs(CSL.OperationalCert.from_bytes, bytes);
exports.operationalCert_toHex = self => self.to_hex();
exports.operationalCert_fromHex = hex_str => errorableToPurs(CSL.OperationalCert.from_hex, hex_str);
exports.operationalCert_toJson = self => self.to_json();
exports.operationalCert_toJsValue = self => self.to_js_value();
exports.operationalCert_fromJson = json => errorableToPurs(CSL.OperationalCert.from_json, json);
exports.operationalCert_hotVkey = self => self.hot_vkey();
exports.operationalCert_sequenceNumber = self => self.sequence_number();
exports.operationalCert_kesPeriod = self => self.kes_period();
exports.operationalCert_sigma = self => self.sigma();
exports.operationalCert_new = hot_vkey => sequence_number => kes_period => sigma => CSL.OperationalCert.new(hot_vkey, sequence_number, kes_period, sigma);

// PlutusData
exports.plutusData_free = self => () => self.free();
exports.plutusData_toBytes = self => self.to_bytes();
exports.plutusData_fromBytes = bytes => errorableToPurs(CSL.PlutusData.from_bytes, bytes);
exports.plutusData_toHex = self => self.to_hex();
exports.plutusData_fromHex = hex_str => errorableToPurs(CSL.PlutusData.from_hex, hex_str);
exports.plutusData_toJson = self => self.to_json();
exports.plutusData_toJsValue = self => self.to_js_value();
exports.plutusData_fromJson = json => errorableToPurs(CSL.PlutusData.from_json, json);
exports.plutusData_newConstrPlutusData = constr_plutus_data => CSL.PlutusData.new_constr_plutus_data(constr_plutus_data);
exports.plutusData_newEmptyConstrPlutusData = alternative => CSL.PlutusData.new_empty_constr_plutus_data(alternative);
exports.plutusData_newMap = map => CSL.PlutusData.new_map(map);
exports.plutusData_newList = list => CSL.PlutusData.new_list(list);
exports.plutusData_newInteger = integer => CSL.PlutusData.new_integer(integer);
exports.plutusData_newBytes = bytes => CSL.PlutusData.new_bytes(bytes);
exports.plutusData_kind = self => self.kind();
exports.plutusData_asConstrPlutusData = self => self.as_constr_plutus_data();
exports.plutusData_asMap = self => self.as_map();
exports.plutusData_asList = self => self.as_list();
exports.plutusData_asInteger = self => self.as_integer();
exports.plutusData_asBytes = self => self.as_bytes();

// PlutusList
exports.plutusList_free = self => () => self.free();
exports.plutusList_toBytes = self => self.to_bytes();
exports.plutusList_fromBytes = bytes => errorableToPurs(CSL.PlutusList.from_bytes, bytes);
exports.plutusList_toHex = self => self.to_hex();
exports.plutusList_fromHex = hex_str => errorableToPurs(CSL.PlutusList.from_hex, hex_str);
exports.plutusList_toJson = self => self.to_json();
exports.plutusList_toJsValue = self => self.to_js_value();
exports.plutusList_fromJson = json => errorableToPurs(CSL.PlutusList.from_json, json);
exports.plutusList_new = () => CSL.PlutusList.new();
exports.plutusList_len = self => () => self.len();
exports.plutusList_get = self => index => () => self.get(index);
exports.plutusList_add = self => elem => () => self.add(elem);

// PlutusMap
exports.plutusMap_free = self => () => self.free();
exports.plutusMap_toBytes = self => self.to_bytes();
exports.plutusMap_fromBytes = bytes => errorableToPurs(CSL.PlutusMap.from_bytes, bytes);
exports.plutusMap_toHex = self => self.to_hex();
exports.plutusMap_fromHex = hex_str => errorableToPurs(CSL.PlutusMap.from_hex, hex_str);
exports.plutusMap_toJson = self => self.to_json();
exports.plutusMap_toJsValue = self => self.to_js_value();
exports.plutusMap_fromJson = json => errorableToPurs(CSL.PlutusMap.from_json, json);
exports.plutusMap_new = () => CSL.PlutusMap.new();
exports.plutusMap_len = self => () => self.len();
exports.plutusMap_insert = self => key => value => () => self.insert(key, value);
exports.plutusMap_get = self => key => () => self.get(key);
exports.plutusMap_keys = self => () => self.keys();

// PlutusScript
exports.plutusScript_free = self => () => self.free();
exports.plutusScript_toBytes = self => self.to_bytes();
exports.plutusScript_fromBytes = bytes => errorableToPurs(CSL.PlutusScript.from_bytes, bytes);
exports.plutusScript_toHex = self => self.to_hex();
exports.plutusScript_fromHex = hex_str => errorableToPurs(CSL.PlutusScript.from_hex, hex_str);
exports.plutusScript_new = bytes => CSL.PlutusScript.new(bytes);
exports.plutusScript_newV2 = bytes => CSL.PlutusScript.new_v2(bytes);
exports.plutusScript_newWithVersion = bytes => language => CSL.PlutusScript.new_with_version(bytes, language);
exports.plutusScript_bytes = self => self.bytes();
exports.plutusScript_fromBytesV2 = bytes => CSL.PlutusScript.from_bytes_v2(bytes);
exports.plutusScript_fromBytesWithVersion = bytes => language => CSL.PlutusScript.from_bytes_with_version(bytes, language);
exports.plutusScript_hash = self => self.hash();
exports.plutusScript_languageVersion = self => self.language_version();

// PlutusScriptSource
exports.plutusScriptSource_free = self => () => self.free();
exports.plutusScriptSource_new = script => CSL.PlutusScriptSource.new(script);
exports.plutusScriptSource_newRefIn = script_hash => input => CSL.PlutusScriptSource.new_ref_input(script_hash, input);

// PlutusScripts
exports.plutusScripts_free = self => () => self.free();
exports.plutusScripts_toBytes = self => self.to_bytes();
exports.plutusScripts_fromBytes = bytes => errorableToPurs(CSL.PlutusScripts.from_bytes, bytes);
exports.plutusScripts_toHex = self => self.to_hex();
exports.plutusScripts_fromHex = hex_str => errorableToPurs(CSL.PlutusScripts.from_hex, hex_str);
exports.plutusScripts_toJson = self => self.to_json();
exports.plutusScripts_toJsValue = self => self.to_js_value();
exports.plutusScripts_fromJson = json => errorableToPurs(CSL.PlutusScripts.from_json, json);
exports.plutusScripts_new = () => CSL.PlutusScripts.new();
exports.plutusScripts_len = self => () => self.len();
exports.plutusScripts_get = self => index => () => self.get(index);
exports.plutusScripts_add = self => elem => () => self.add(elem);

// PlutusWitness
exports.plutusWitness_free = self => () => self.free();
exports.plutusWitness_new = script => datum => redeemer => CSL.PlutusWitness.new(script, datum, redeemer);
exports.plutusWitness_newWithRef = script => datum => redeemer => CSL.PlutusWitness.new_with_ref(script, datum, redeemer);
exports.plutusWitness_script = self => self.script();
exports.plutusWitness_datum = self => self.datum();
exports.plutusWitness_redeemer = self => self.redeemer();

// PlutusWitnesses
exports.plutusWitnesses_free = self => () => self.free();
exports.plutusWitnesses_new = () => CSL.PlutusWitnesses.new();
exports.plutusWitnesses_len = self => () => self.len();
exports.plutusWitnesses_get = self => index => () => self.get(index);
exports.plutusWitnesses_add = self => elem => () => self.add(elem);

// Pointer
exports.pointer_free = self => () => self.free();
exports.pointer_new = slot => tx_index => cert_index => CSL.Pointer.new(slot, tx_index, cert_index);
exports.pointer_newPointer = slot => tx_index => cert_index => CSL.Pointer.new_pointer(slot, tx_index, cert_index);
exports.pointer_slot = self => self.slot();
exports.pointer_txIndex = self => self.tx_index();
exports.pointer_certIndex = self => self.cert_index();
exports.pointer_slotBignum = self => self.slot_bignum();
exports.pointer_txIndexBignum = self => self.tx_index_bignum();
exports.pointer_certIndexBignum = self => self.cert_index_bignum();

// PointerAddress
exports.pointerAddress_free = self => () => self.free();
exports.pointerAddress_new = network => payment => stake => CSL.PointerAddress.new(network, payment, stake);
exports.pointerAddress_paymentCred = self => self.payment_cred();
exports.pointerAddress_stakePointer = self => self.stake_pointer();
exports.pointerAddress_toAddress = self => self.to_address();
exports.pointerAddress_fromAddress = addr => CSL.PointerAddress.from_address(addr);

// PoolMetadata
exports.poolMetadata_free = self => () => self.free();
exports.poolMetadata_toBytes = self => self.to_bytes();
exports.poolMetadata_fromBytes = bytes => errorableToPurs(CSL.PoolMetadata.from_bytes, bytes);
exports.poolMetadata_toHex = self => self.to_hex();
exports.poolMetadata_fromHex = hex_str => errorableToPurs(CSL.PoolMetadata.from_hex, hex_str);
exports.poolMetadata_toJson = self => self.to_json();
exports.poolMetadata_toJsValue = self => self.to_js_value();
exports.poolMetadata_fromJson = json => errorableToPurs(CSL.PoolMetadata.from_json, json);
exports.poolMetadata_url = self => self.url();
exports.poolMetadata_poolMetadataHash = self => self.pool_metadata_hash();
exports.poolMetadata_new = url => pool_metadata_hash => CSL.PoolMetadata.new(url, pool_metadata_hash);

// PoolMetadataHash
exports.poolMetadataHash_free = self => () => self.free();
exports.poolMetadataHash_fromBytes = bytes => errorableToPurs(CSL.PoolMetadataHash.from_bytes, bytes);
exports.poolMetadataHash_toBytes = self => self.to_bytes();
exports.poolMetadataHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.poolMetadataHash_fromBech32 = bech_str => errorableToPurs(CSL.PoolMetadataHash.from_bech32, bech_str);
exports.poolMetadataHash_toHex = self => self.to_hex();
exports.poolMetadataHash_fromHex = hex => errorableToPurs(CSL.PoolMetadataHash.from_hex, hex);

// PoolParams
exports.poolParams_free = self => () => self.free();
exports.poolParams_toBytes = self => self.to_bytes();
exports.poolParams_fromBytes = bytes => errorableToPurs(CSL.PoolParams.from_bytes, bytes);
exports.poolParams_toHex = self => self.to_hex();
exports.poolParams_fromHex = hex_str => errorableToPurs(CSL.PoolParams.from_hex, hex_str);
exports.poolParams_toJson = self => self.to_json();
exports.poolParams_toJsValue = self => self.to_js_value();
exports.poolParams_fromJson = json => errorableToPurs(CSL.PoolParams.from_json, json);
exports.poolParams_operator = self => self.operator();
exports.poolParams_vrfKeyhash = self => self.vrf_keyhash();
exports.poolParams_pledge = self => self.pledge();
exports.poolParams_cost = self => self.cost();
exports.poolParams_margin = self => self.margin();
exports.poolParams_rewardAccount = self => self.reward_account();
exports.poolParams_poolOwners = self => self.pool_owners();
exports.poolParams_relays = self => self.relays();
exports.poolParams_poolMetadata = self => self.pool_metadata();
exports.poolParams_new = operator => vrf_keyhash => pledge => cost => margin => reward_account => pool_owners => relays => pool_metadata => CSL.PoolParams.new(operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, pool_metadata);

// PoolRegistration
exports.poolRegistration_free = self => () => self.free();
exports.poolRegistration_toBytes = self => self.to_bytes();
exports.poolRegistration_fromBytes = bytes => errorableToPurs(CSL.PoolRegistration.from_bytes, bytes);
exports.poolRegistration_toHex = self => self.to_hex();
exports.poolRegistration_fromHex = hex_str => errorableToPurs(CSL.PoolRegistration.from_hex, hex_str);
exports.poolRegistration_toJson = self => self.to_json();
exports.poolRegistration_toJsValue = self => self.to_js_value();
exports.poolRegistration_fromJson = json => errorableToPurs(CSL.PoolRegistration.from_json, json);
exports.poolRegistration_poolParams = self => self.pool_params();
exports.poolRegistration_new = pool_params => CSL.PoolRegistration.new(pool_params);

// PoolRetirement
exports.poolRetirement_free = self => () => self.free();
exports.poolRetirement_toBytes = self => self.to_bytes();
exports.poolRetirement_fromBytes = bytes => errorableToPurs(CSL.PoolRetirement.from_bytes, bytes);
exports.poolRetirement_toHex = self => self.to_hex();
exports.poolRetirement_fromHex = hex_str => errorableToPurs(CSL.PoolRetirement.from_hex, hex_str);
exports.poolRetirement_toJson = self => self.to_json();
exports.poolRetirement_toJsValue = self => self.to_js_value();
exports.poolRetirement_fromJson = json => errorableToPurs(CSL.PoolRetirement.from_json, json);
exports.poolRetirement_poolKeyhash = self => self.pool_keyhash();
exports.poolRetirement_epoch = self => self.epoch();
exports.poolRetirement_new = pool_keyhash => epoch => CSL.PoolRetirement.new(pool_keyhash, epoch);

// PrivateKey
exports.privateKey_free = self => () => self.free();
exports.privateKey_toPublic = self => self.to_public();
exports.privateKey_generateEd25519 = CSL.PrivateKey.generate_ed25519();
exports.privateKey_generateEd25519extended = CSL.PrivateKey.generate_ed25519extended();
exports.privateKey_fromBech32 = bech32_str => errorableToPurs(CSL.PrivateKey.from_bech32, bech32_str);
exports.privateKey_toBech32 = self => self.to_bech32();
exports.privateKey_asBytes = self => self.as_bytes();
exports.privateKey_fromExtendedBytes = bytes => CSL.PrivateKey.from_extended_bytes(bytes);
exports.privateKey_fromNormalBytes = bytes => CSL.PrivateKey.from_normal_bytes(bytes);
exports.privateKey_sign = self => message => self.sign(message);
exports.privateKey_toHex = self => self.to_hex();
exports.privateKey_fromHex = hex_str => errorableToPurs(CSL.PrivateKey.from_hex, hex_str);

// ProposedProtocolParameterUpdates
exports.proposedProtocolParameterUpdates_free = self => () => self.free();
exports.proposedProtocolParameterUpdates_toBytes = self => self.to_bytes();
exports.proposedProtocolParameterUpdates_fromBytes = bytes => errorableToPurs(CSL.ProposedProtocolParameterUpdates.from_bytes, bytes);
exports.proposedProtocolParameterUpdates_toHex = self => self.to_hex();
exports.proposedProtocolParameterUpdates_fromHex = hex_str => errorableToPurs(CSL.ProposedProtocolParameterUpdates.from_hex, hex_str);
exports.proposedProtocolParameterUpdates_toJson = self => self.to_json();
exports.proposedProtocolParameterUpdates_toJsValue = self => self.to_js_value();
exports.proposedProtocolParameterUpdates_fromJson = json => errorableToPurs(CSL.ProposedProtocolParameterUpdates.from_json, json);
exports.proposedProtocolParameterUpdates_new = () => CSL.ProposedProtocolParameterUpdates.new();
exports.proposedProtocolParameterUpdates_len = self => () => self.len();
exports.proposedProtocolParameterUpdates_insert = self => key => value => () => self.insert(key, value);
exports.proposedProtocolParameterUpdates_get = self => key => () => self.get(key);
exports.proposedProtocolParameterUpdates_keys = self => () => self.keys();

// ProtocolParamUpdate
exports.protocolParamUpdate_free = self => () => self.free();
exports.protocolParamUpdate_toBytes = self => self.to_bytes();
exports.protocolParamUpdate_fromBytes = bytes => errorableToPurs(CSL.ProtocolParamUpdate.from_bytes, bytes);
exports.protocolParamUpdate_toHex = self => self.to_hex();
exports.protocolParamUpdate_fromHex = hex_str => errorableToPurs(CSL.ProtocolParamUpdate.from_hex, hex_str);
exports.protocolParamUpdate_toJson = self => self.to_json();
exports.protocolParamUpdate_toJsValue = self => self.to_js_value();
exports.protocolParamUpdate_fromJson = json => errorableToPurs(CSL.ProtocolParamUpdate.from_json, json);
exports.protocolParamUpdate_setMinfeeA = self => minfee_a => () => self.set_minfee_a(minfee_a);
exports.protocolParamUpdate_minfeeA = self => self.minfee_a();
exports.protocolParamUpdate_setMinfeeB = self => minfee_b => () => self.set_minfee_b(minfee_b);
exports.protocolParamUpdate_minfeeB = self => self.minfee_b();
exports.protocolParamUpdate_setMaxBlockBodySize = self => max_block_body_size => () => self.set_max_block_body_size(max_block_body_size);
exports.protocolParamUpdate_maxBlockBodySize = self => self.max_block_body_size();
exports.protocolParamUpdate_setMaxTxSize = self => max_tx_size => () => self.set_max_tx_size(max_tx_size);
exports.protocolParamUpdate_maxTxSize = self => self.max_tx_size();
exports.protocolParamUpdate_setMaxBlockHeaderSize = self => max_block_header_size => () => self.set_max_block_header_size(max_block_header_size);
exports.protocolParamUpdate_maxBlockHeaderSize = self => self.max_block_header_size();
exports.protocolParamUpdate_setKeyDeposit = self => key_deposit => () => self.set_key_deposit(key_deposit);
exports.protocolParamUpdate_keyDeposit = self => self.key_deposit();
exports.protocolParamUpdate_setPoolDeposit = self => pool_deposit => () => self.set_pool_deposit(pool_deposit);
exports.protocolParamUpdate_poolDeposit = self => self.pool_deposit();
exports.protocolParamUpdate_setMaxEpoch = self => max_epoch => () => self.set_max_epoch(max_epoch);
exports.protocolParamUpdate_maxEpoch = self => self.max_epoch();
exports.protocolParamUpdate_setNOpt = self => n_opt => () => self.set_n_opt(n_opt);
exports.protocolParamUpdate_nOpt = self => self.n_opt();
exports.protocolParamUpdate_setPoolPledgeInfluence = self => pool_pledge_influence => () => self.set_pool_pledge_influence(pool_pledge_influence);
exports.protocolParamUpdate_poolPledgeInfluence = self => self.pool_pledge_influence();
exports.protocolParamUpdate_setExpansionRate = self => expansion_rate => () => self.set_expansion_rate(expansion_rate);
exports.protocolParamUpdate_expansionRate = self => self.expansion_rate();
exports.protocolParamUpdate_setTreasuryGrowthRate = self => treasury_growth_rate => () => self.set_treasury_growth_rate(treasury_growth_rate);
exports.protocolParamUpdate_treasuryGrowthRate = self => self.treasury_growth_rate();
exports.protocolParamUpdate_d = self => self.d();
exports.protocolParamUpdate_extraEntropy = self => self.extra_entropy();
exports.protocolParamUpdate_setProtocolVersion = self => protocol_version => () => self.set_protocol_version(protocol_version);
exports.protocolParamUpdate_protocolVersion = self => self.protocol_version();
exports.protocolParamUpdate_setMinPoolCost = self => min_pool_cost => () => self.set_min_pool_cost(min_pool_cost);
exports.protocolParamUpdate_minPoolCost = self => self.min_pool_cost();
exports.protocolParamUpdate_setAdaPerUtxoByte = self => ada_per_utxo_byte => () => self.set_ada_per_utxo_byte(ada_per_utxo_byte);
exports.protocolParamUpdate_adaPerUtxoByte = self => self.ada_per_utxo_byte();
exports.protocolParamUpdate_setCostModels = self => cost_models => () => self.set_cost_models(cost_models);
exports.protocolParamUpdate_costModels = self => self.cost_models();
exports.protocolParamUpdate_setExecutionCosts = self => execution_costs => () => self.set_execution_costs(execution_costs);
exports.protocolParamUpdate_executionCosts = self => self.execution_costs();
exports.protocolParamUpdate_setMaxTxExUnits = self => max_tx_ex_units => () => self.set_max_tx_ex_units(max_tx_ex_units);
exports.protocolParamUpdate_maxTxExUnits = self => self.max_tx_ex_units();
exports.protocolParamUpdate_setMaxBlockExUnits = self => max_block_ex_units => () => self.set_max_block_ex_units(max_block_ex_units);
exports.protocolParamUpdate_maxBlockExUnits = self => self.max_block_ex_units();
exports.protocolParamUpdate_setMaxValueSize = self => max_value_size => () => self.set_max_value_size(max_value_size);
exports.protocolParamUpdate_maxValueSize = self => self.max_value_size();
exports.protocolParamUpdate_setCollateralPercentage = self => collateral_percentage => () => self.set_collateral_percentage(collateral_percentage);
exports.protocolParamUpdate_collateralPercentage = self => self.collateral_percentage();
exports.protocolParamUpdate_setMaxCollateralIns = self => max_collateral_inputs => () => self.set_max_collateral_inputs(max_collateral_inputs);
exports.protocolParamUpdate_maxCollateralIns = self => self.max_collateral_inputs();
exports.protocolParamUpdate_new = CSL.ProtocolParamUpdate.new();

// ProtocolVersion
exports.protocolVersion_free = self => () => self.free();
exports.protocolVersion_toBytes = self => self.to_bytes();
exports.protocolVersion_fromBytes = bytes => errorableToPurs(CSL.ProtocolVersion.from_bytes, bytes);
exports.protocolVersion_toHex = self => self.to_hex();
exports.protocolVersion_fromHex = hex_str => errorableToPurs(CSL.ProtocolVersion.from_hex, hex_str);
exports.protocolVersion_toJson = self => self.to_json();
exports.protocolVersion_toJsValue = self => self.to_js_value();
exports.protocolVersion_fromJson = json => errorableToPurs(CSL.ProtocolVersion.from_json, json);
exports.protocolVersion_major = self => self.major();
exports.protocolVersion_minor = self => self.minor();
exports.protocolVersion_new = major => minor => CSL.ProtocolVersion.new(major, minor);

// PublicKey
exports.publicKey_free = self => () => self.free();
exports.publicKey_fromBech32 = bech32_str => errorableToPurs(CSL.PublicKey.from_bech32, bech32_str);
exports.publicKey_toBech32 = self => self.to_bech32();
exports.publicKey_asBytes = self => self.as_bytes();
exports.publicKey_fromBytes = bytes => errorableToPurs(CSL.PublicKey.from_bytes, bytes);
exports.publicKey_verify = self => data => signature => self.verify(data, signature);
exports.publicKey_hash = self => self.hash();
exports.publicKey_toHex = self => self.to_hex();
exports.publicKey_fromHex = hex_str => errorableToPurs(CSL.PublicKey.from_hex, hex_str);

// PublicKeys
exports.publicKeys_free = self => () => self.free();
exports.publicKeys_constructor = self => self.constructor();
exports.publicKeys_size = self => self.size();
exports.publicKeys_get = self => index => self.get(index);
exports.publicKeys_add = self => key => () => self.add(key);

// Redeemer
exports.redeemer_free = self => () => self.free();
exports.redeemer_toBytes = self => self.to_bytes();
exports.redeemer_fromBytes = bytes => errorableToPurs(CSL.Redeemer.from_bytes, bytes);
exports.redeemer_toHex = self => self.to_hex();
exports.redeemer_fromHex = hex_str => errorableToPurs(CSL.Redeemer.from_hex, hex_str);
exports.redeemer_toJson = self => self.to_json();
exports.redeemer_toJsValue = self => self.to_js_value();
exports.redeemer_fromJson = json => errorableToPurs(CSL.Redeemer.from_json, json);
exports.redeemer_tag = self => self.tag();
exports.redeemer_index = self => self.index();
exports.redeemer_data = self => self.data();
exports.redeemer_exUnits = self => self.ex_units();
exports.redeemer_new = tag => index => data => ex_units => CSL.Redeemer.new(tag, index, data, ex_units);

// RedeemerTag
exports.redeemerTag_free = self => () => self.free();
exports.redeemerTag_toBytes = self => self.to_bytes();
exports.redeemerTag_fromBytes = bytes => errorableToPurs(CSL.RedeemerTag.from_bytes, bytes);
exports.redeemerTag_toHex = self => self.to_hex();
exports.redeemerTag_fromHex = hex_str => errorableToPurs(CSL.RedeemerTag.from_hex, hex_str);
exports.redeemerTag_toJson = self => self.to_json();
exports.redeemerTag_toJsValue = self => self.to_js_value();
exports.redeemerTag_fromJson = json => errorableToPurs(CSL.RedeemerTag.from_json, json);
exports.redeemerTag_newSpend = CSL.RedeemerTag.new_spend();
exports.redeemerTag_newMint = CSL.RedeemerTag.new_mint();
exports.redeemerTag_newCert = CSL.RedeemerTag.new_cert();
exports.redeemerTag_newReward = CSL.RedeemerTag.new_reward();
exports.redeemerTag_kind = self => self.kind();

// Redeemers
exports.redeemers_free = self => () => self.free();
exports.redeemers_toBytes = self => self.to_bytes();
exports.redeemers_fromBytes = bytes => errorableToPurs(CSL.Redeemers.from_bytes, bytes);
exports.redeemers_toHex = self => self.to_hex();
exports.redeemers_fromHex = hex_str => errorableToPurs(CSL.Redeemers.from_hex, hex_str);
exports.redeemers_toJson = self => self.to_json();
exports.redeemers_toJsValue = self => self.to_js_value();
exports.redeemers_fromJson = json => errorableToPurs(CSL.Redeemers.from_json, json);
exports.redeemers_new = () => CSL.Redeemers.new();
exports.redeemers_len = self => () => self.len();
exports.redeemers_get = self => index => () => self.get(index);
exports.redeemers_add = self => elem => () => self.add(elem);
exports.redeemers_totalExUnits = self => self.total_ex_units();

// Relay
exports.relay_free = self => () => self.free();
exports.relay_toBytes = self => self.to_bytes();
exports.relay_fromBytes = bytes => errorableToPurs(CSL.Relay.from_bytes, bytes);
exports.relay_toHex = self => self.to_hex();
exports.relay_fromHex = hex_str => errorableToPurs(CSL.Relay.from_hex, hex_str);
exports.relay_toJson = self => self.to_json();
exports.relay_toJsValue = self => self.to_js_value();
exports.relay_fromJson = json => errorableToPurs(CSL.Relay.from_json, json);
exports.relay_newSingleHostAddr = single_host_addr => CSL.Relay.new_single_host_addr(single_host_addr);
exports.relay_newSingleHostName = single_host_name => CSL.Relay.new_single_host_name(single_host_name);
exports.relay_newMultiHostName = multi_host_name => CSL.Relay.new_multi_host_name(multi_host_name);
exports.relay_kind = self => self.kind();
exports.relay_asSingleHostAddr = self => self.as_single_host_addr();
exports.relay_asSingleHostName = self => self.as_single_host_name();
exports.relay_asMultiHostName = self => self.as_multi_host_name();

// Relays
exports.relays_free = self => () => self.free();
exports.relays_toBytes = self => self.to_bytes();
exports.relays_fromBytes = bytes => errorableToPurs(CSL.Relays.from_bytes, bytes);
exports.relays_toHex = self => self.to_hex();
exports.relays_fromHex = hex_str => errorableToPurs(CSL.Relays.from_hex, hex_str);
exports.relays_toJson = self => self.to_json();
exports.relays_toJsValue = self => self.to_js_value();
exports.relays_fromJson = json => errorableToPurs(CSL.Relays.from_json, json);
exports.relays_new = () => CSL.Relays.new();
exports.relays_len = self => () => self.len();
exports.relays_get = self => index => () => self.get(index);
exports.relays_add = self => elem => () => self.add(elem);

// RewardAddress
exports.rewardAddress_free = self => () => self.free();
exports.rewardAddress_new = network => payment => CSL.RewardAddress.new(network, payment);
exports.rewardAddress_paymentCred = self => self.payment_cred();
exports.rewardAddress_toAddress = self => self.to_address();
exports.rewardAddress_fromAddress = addr => CSL.RewardAddress.from_address(addr);

// RewardAddresses
exports.rewardAddresses_free = self => () => self.free();
exports.rewardAddresses_toBytes = self => self.to_bytes();
exports.rewardAddresses_fromBytes = bytes => errorableToPurs(CSL.RewardAddresses.from_bytes, bytes);
exports.rewardAddresses_toHex = self => self.to_hex();
exports.rewardAddresses_fromHex = hex_str => errorableToPurs(CSL.RewardAddresses.from_hex, hex_str);
exports.rewardAddresses_toJson = self => self.to_json();
exports.rewardAddresses_toJsValue = self => self.to_js_value();
exports.rewardAddresses_fromJson = json => errorableToPurs(CSL.RewardAddresses.from_json, json);
exports.rewardAddresses_new = () => CSL.RewardAddresses.new();
exports.rewardAddresses_len = self => () => self.len();
exports.rewardAddresses_get = self => index => () => self.get(index);
exports.rewardAddresses_add = self => elem => () => self.add(elem);

// ScriptAll
exports.scriptAll_free = self => () => self.free();
exports.scriptAll_toBytes = self => self.to_bytes();
exports.scriptAll_fromBytes = bytes => errorableToPurs(CSL.ScriptAll.from_bytes, bytes);
exports.scriptAll_toHex = self => self.to_hex();
exports.scriptAll_fromHex = hex_str => errorableToPurs(CSL.ScriptAll.from_hex, hex_str);
exports.scriptAll_toJson = self => self.to_json();
exports.scriptAll_toJsValue = self => self.to_js_value();
exports.scriptAll_fromJson = json => errorableToPurs(CSL.ScriptAll.from_json, json);
exports.scriptAll_nativeScripts = self => self.native_scripts();
exports.scriptAll_new = native_scripts => CSL.ScriptAll.new(native_scripts);

// ScriptAny
exports.scriptAny_free = self => () => self.free();
exports.scriptAny_toBytes = self => self.to_bytes();
exports.scriptAny_fromBytes = bytes => errorableToPurs(CSL.ScriptAny.from_bytes, bytes);
exports.scriptAny_toHex = self => self.to_hex();
exports.scriptAny_fromHex = hex_str => errorableToPurs(CSL.ScriptAny.from_hex, hex_str);
exports.scriptAny_toJson = self => self.to_json();
exports.scriptAny_toJsValue = self => self.to_js_value();
exports.scriptAny_fromJson = json => errorableToPurs(CSL.ScriptAny.from_json, json);
exports.scriptAny_nativeScripts = self => self.native_scripts();
exports.scriptAny_new = native_scripts => CSL.ScriptAny.new(native_scripts);

// ScriptDataHash
exports.scriptDataHash_free = self => () => self.free();
exports.scriptDataHash_fromBytes = bytes => errorableToPurs(CSL.ScriptDataHash.from_bytes, bytes);
exports.scriptDataHash_toBytes = self => self.to_bytes();
exports.scriptDataHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.scriptDataHash_fromBech32 = bech_str => errorableToPurs(CSL.ScriptDataHash.from_bech32, bech_str);
exports.scriptDataHash_toHex = self => self.to_hex();
exports.scriptDataHash_fromHex = hex => errorableToPurs(CSL.ScriptDataHash.from_hex, hex);

// ScriptHash
exports.scriptHash_free = self => () => self.free();
exports.scriptHash_fromBytes = bytes => errorableToPurs(CSL.ScriptHash.from_bytes, bytes);
exports.scriptHash_toBytes = self => self.to_bytes();
exports.scriptHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.scriptHash_fromBech32 = bech_str => errorableToPurs(CSL.ScriptHash.from_bech32, bech_str);
exports.scriptHash_toHex = self => self.to_hex();
exports.scriptHash_fromHex = hex => errorableToPurs(CSL.ScriptHash.from_hex, hex);

// ScriptHashes
exports.scriptHashes_free = self => () => self.free();
exports.scriptHashes_toBytes = self => self.to_bytes();
exports.scriptHashes_fromBytes = bytes => errorableToPurs(CSL.ScriptHashes.from_bytes, bytes);
exports.scriptHashes_toHex = self => self.to_hex();
exports.scriptHashes_fromHex = hex_str => errorableToPurs(CSL.ScriptHashes.from_hex, hex_str);
exports.scriptHashes_toJson = self => self.to_json();
exports.scriptHashes_toJsValue = self => self.to_js_value();
exports.scriptHashes_fromJson = json => errorableToPurs(CSL.ScriptHashes.from_json, json);
exports.scriptHashes_new = () => CSL.ScriptHashes.new();
exports.scriptHashes_len = self => () => self.len();
exports.scriptHashes_get = self => index => () => self.get(index);
exports.scriptHashes_add = self => elem => () => self.add(elem);

// ScriptNOfK
exports.scriptNOfK_free = self => () => self.free();
exports.scriptNOfK_toBytes = self => self.to_bytes();
exports.scriptNOfK_fromBytes = bytes => errorableToPurs(CSL.ScriptNOfK.from_bytes, bytes);
exports.scriptNOfK_toHex = self => self.to_hex();
exports.scriptNOfK_fromHex = hex_str => errorableToPurs(CSL.ScriptNOfK.from_hex, hex_str);
exports.scriptNOfK_toJson = self => self.to_json();
exports.scriptNOfK_toJsValue = self => self.to_js_value();
exports.scriptNOfK_fromJson = json => errorableToPurs(CSL.ScriptNOfK.from_json, json);
exports.scriptNOfK_n = self => self.n();
exports.scriptNOfK_nativeScripts = self => self.native_scripts();
exports.scriptNOfK_new = n => native_scripts => CSL.ScriptNOfK.new(n, native_scripts);

// ScriptPubkey
exports.scriptPubkey_free = self => () => self.free();
exports.scriptPubkey_toBytes = self => self.to_bytes();
exports.scriptPubkey_fromBytes = bytes => errorableToPurs(CSL.ScriptPubkey.from_bytes, bytes);
exports.scriptPubkey_toHex = self => self.to_hex();
exports.scriptPubkey_fromHex = hex_str => errorableToPurs(CSL.ScriptPubkey.from_hex, hex_str);
exports.scriptPubkey_toJson = self => self.to_json();
exports.scriptPubkey_toJsValue = self => self.to_js_value();
exports.scriptPubkey_fromJson = json => errorableToPurs(CSL.ScriptPubkey.from_json, json);
exports.scriptPubkey_addrKeyhash = self => self.addr_keyhash();
exports.scriptPubkey_new = addr_keyhash => CSL.ScriptPubkey.new(addr_keyhash);

// ScriptRef
exports.scriptRef_free = self => () => self.free();
exports.scriptRef_toBytes = self => self.to_bytes();
exports.scriptRef_fromBytes = bytes => errorableToPurs(CSL.ScriptRef.from_bytes, bytes);
exports.scriptRef_toHex = self => self.to_hex();
exports.scriptRef_fromHex = hex_str => errorableToPurs(CSL.ScriptRef.from_hex, hex_str);
exports.scriptRef_toJson = self => self.to_json();
exports.scriptRef_toJsValue = self => self.to_js_value();
exports.scriptRef_fromJson = json => errorableToPurs(CSL.ScriptRef.from_json, json);
exports.scriptRef_newNativeScript = native_script => CSL.ScriptRef.new_native_script(native_script);
exports.scriptRef_newPlutusScript = plutus_script => CSL.ScriptRef.new_plutus_script(plutus_script);
exports.scriptRef_isNativeScript = self => self.is_native_script();
exports.scriptRef_isPlutusScript = self => self.is_plutus_script();
exports.scriptRef_nativeScript = self => self.native_script();
exports.scriptRef_plutusScript = self => self.plutus_script();

// SingleHostAddr
exports.singleHostAddr_free = self => () => self.free();
exports.singleHostAddr_toBytes = self => self.to_bytes();
exports.singleHostAddr_fromBytes = bytes => errorableToPurs(CSL.SingleHostAddr.from_bytes, bytes);
exports.singleHostAddr_toHex = self => self.to_hex();
exports.singleHostAddr_fromHex = hex_str => errorableToPurs(CSL.SingleHostAddr.from_hex, hex_str);
exports.singleHostAddr_toJson = self => self.to_json();
exports.singleHostAddr_toJsValue = self => self.to_js_value();
exports.singleHostAddr_fromJson = json => errorableToPurs(CSL.SingleHostAddr.from_json, json);
exports.singleHostAddr_port = self => self.port();
exports.singleHostAddr_ipv4 = self => self.ipv4();
exports.singleHostAddr_ipv6 = self => self.ipv6();
exports.singleHostAddr_new = port => ipv4 => ipv6 => CSL.SingleHostAddr.new(port, ipv4, ipv6);

// SingleHostName
exports.singleHostName_free = self => () => self.free();
exports.singleHostName_toBytes = self => self.to_bytes();
exports.singleHostName_fromBytes = bytes => errorableToPurs(CSL.SingleHostName.from_bytes, bytes);
exports.singleHostName_toHex = self => self.to_hex();
exports.singleHostName_fromHex = hex_str => errorableToPurs(CSL.SingleHostName.from_hex, hex_str);
exports.singleHostName_toJson = self => self.to_json();
exports.singleHostName_toJsValue = self => self.to_js_value();
exports.singleHostName_fromJson = json => errorableToPurs(CSL.SingleHostName.from_json, json);
exports.singleHostName_port = self => self.port();
exports.singleHostName_dnsName = self => self.dns_name();
exports.singleHostName_new = port => dns_name => CSL.SingleHostName.new(port, dns_name);

// StakeCredential
exports.stakeCredential_free = self => () => self.free();
exports.stakeCredential_fromKeyhash = hash => CSL.StakeCredential.from_keyhash(hash);
exports.stakeCredential_fromScripthash = hash => CSL.StakeCredential.from_scripthash(hash);
exports.stakeCredential_toKeyhash = self => self.to_keyhash();
exports.stakeCredential_toScripthash = self => self.to_scripthash();
exports.stakeCredential_kind = self => self.kind();
exports.stakeCredential_toBytes = self => self.to_bytes();
exports.stakeCredential_fromBytes = bytes => errorableToPurs(CSL.StakeCredential.from_bytes, bytes);
exports.stakeCredential_toHex = self => self.to_hex();
exports.stakeCredential_fromHex = hex_str => errorableToPurs(CSL.StakeCredential.from_hex, hex_str);
exports.stakeCredential_toJson = self => self.to_json();
exports.stakeCredential_toJsValue = self => self.to_js_value();
exports.stakeCredential_fromJson = json => errorableToPurs(CSL.StakeCredential.from_json, json);

// StakeCredentials
exports.stakeCredentials_free = self => () => self.free();
exports.stakeCredentials_toBytes = self => self.to_bytes();
exports.stakeCredentials_fromBytes = bytes => errorableToPurs(CSL.StakeCredentials.from_bytes, bytes);
exports.stakeCredentials_toHex = self => self.to_hex();
exports.stakeCredentials_fromHex = hex_str => errorableToPurs(CSL.StakeCredentials.from_hex, hex_str);
exports.stakeCredentials_toJson = self => self.to_json();
exports.stakeCredentials_toJsValue = self => self.to_js_value();
exports.stakeCredentials_fromJson = json => errorableToPurs(CSL.StakeCredentials.from_json, json);
exports.stakeCredentials_new = () => CSL.StakeCredentials.new();
exports.stakeCredentials_len = self => () => self.len();
exports.stakeCredentials_get = self => index => () => self.get(index);
exports.stakeCredentials_add = self => elem => () => self.add(elem);

// StakeDelegation
exports.stakeDelegation_free = self => () => self.free();
exports.stakeDelegation_toBytes = self => self.to_bytes();
exports.stakeDelegation_fromBytes = bytes => errorableToPurs(CSL.StakeDelegation.from_bytes, bytes);
exports.stakeDelegation_toHex = self => self.to_hex();
exports.stakeDelegation_fromHex = hex_str => errorableToPurs(CSL.StakeDelegation.from_hex, hex_str);
exports.stakeDelegation_toJson = self => self.to_json();
exports.stakeDelegation_toJsValue = self => self.to_js_value();
exports.stakeDelegation_fromJson = json => errorableToPurs(CSL.StakeDelegation.from_json, json);
exports.stakeDelegation_stakeCredential = self => self.stake_credential();
exports.stakeDelegation_poolKeyhash = self => self.pool_keyhash();
exports.stakeDelegation_new = stake_credential => pool_keyhash => CSL.StakeDelegation.new(stake_credential, pool_keyhash);

// StakeDeregistration
exports.stakeDeregistration_free = self => () => self.free();
exports.stakeDeregistration_toBytes = self => self.to_bytes();
exports.stakeDeregistration_fromBytes = bytes => errorableToPurs(CSL.StakeDeregistration.from_bytes, bytes);
exports.stakeDeregistration_toHex = self => self.to_hex();
exports.stakeDeregistration_fromHex = hex_str => errorableToPurs(CSL.StakeDeregistration.from_hex, hex_str);
exports.stakeDeregistration_toJson = self => self.to_json();
exports.stakeDeregistration_toJsValue = self => self.to_js_value();
exports.stakeDeregistration_fromJson = json => errorableToPurs(CSL.StakeDeregistration.from_json, json);
exports.stakeDeregistration_stakeCredential = self => self.stake_credential();
exports.stakeDeregistration_new = stake_credential => CSL.StakeDeregistration.new(stake_credential);

// StakeRegistration
exports.stakeRegistration_free = self => () => self.free();
exports.stakeRegistration_toBytes = self => self.to_bytes();
exports.stakeRegistration_fromBytes = bytes => errorableToPurs(CSL.StakeRegistration.from_bytes, bytes);
exports.stakeRegistration_toHex = self => self.to_hex();
exports.stakeRegistration_fromHex = hex_str => errorableToPurs(CSL.StakeRegistration.from_hex, hex_str);
exports.stakeRegistration_toJson = self => self.to_json();
exports.stakeRegistration_toJsValue = self => self.to_js_value();
exports.stakeRegistration_fromJson = json => errorableToPurs(CSL.StakeRegistration.from_json, json);
exports.stakeRegistration_stakeCredential = self => self.stake_credential();
exports.stakeRegistration_new = stake_credential => CSL.StakeRegistration.new(stake_credential);

// Strings
exports.strings_free = self => () => self.free();
exports.strings_new = () => CSL.Strings.new();
exports.strings_len = self => () => self.len();
exports.strings_get = self => index => () => self.get(index);
exports.strings_add = self => elem => () => self.add(elem);

// TimelockExpiry
exports.timelockExpiry_free = self => () => self.free();
exports.timelockExpiry_toBytes = self => self.to_bytes();
exports.timelockExpiry_fromBytes = bytes => errorableToPurs(CSL.TimelockExpiry.from_bytes, bytes);
exports.timelockExpiry_toHex = self => self.to_hex();
exports.timelockExpiry_fromHex = hex_str => errorableToPurs(CSL.TimelockExpiry.from_hex, hex_str);
exports.timelockExpiry_toJson = self => self.to_json();
exports.timelockExpiry_toJsValue = self => self.to_js_value();
exports.timelockExpiry_fromJson = json => errorableToPurs(CSL.TimelockExpiry.from_json, json);
exports.timelockExpiry_slot = self => self.slot();
exports.timelockExpiry_slotBignum = self => self.slot_bignum();
exports.timelockExpiry_new = slot => CSL.TimelockExpiry.new(slot);
exports.timelockExpiry_newTimelockexpiry = slot => CSL.TimelockExpiry.new_timelockexpiry(slot);

// TimelockStart
exports.timelockStart_free = self => () => self.free();
exports.timelockStart_toBytes = self => self.to_bytes();
exports.timelockStart_fromBytes = bytes => errorableToPurs(CSL.TimelockStart.from_bytes, bytes);
exports.timelockStart_toHex = self => self.to_hex();
exports.timelockStart_fromHex = hex_str => errorableToPurs(CSL.TimelockStart.from_hex, hex_str);
exports.timelockStart_toJson = self => self.to_json();
exports.timelockStart_toJsValue = self => self.to_js_value();
exports.timelockStart_fromJson = json => errorableToPurs(CSL.TimelockStart.from_json, json);
exports.timelockStart_slot = self => self.slot();
exports.timelockStart_slotBignum = self => self.slot_bignum();
exports.timelockStart_new = slot => CSL.TimelockStart.new(slot);
exports.timelockStart_newTimelockstart = slot => CSL.TimelockStart.new_timelockstart(slot);

// Transaction
exports.tx_free = self => () => self.free();
exports.tx_toBytes = self => self.to_bytes();
exports.tx_fromBytes = bytes => errorableToPurs(CSL.Transaction.from_bytes, bytes);
exports.tx_toHex = self => self.to_hex();
exports.tx_fromHex = hex_str => errorableToPurs(CSL.Transaction.from_hex, hex_str);
exports.tx_toJson = self => self.to_json();
exports.tx_toJsValue = self => self.to_js_value();
exports.tx_fromJson = json => errorableToPurs(CSL.Transaction.from_json, json);
exports.tx_body = self => self.body();
exports.tx_witnessSet = self => self.witness_set();
exports.tx_isValid = self => self.is_valid();
exports.tx_auxiliaryData = self => self.auxiliary_data();
exports.tx_setIsValid = self => valid => () => self.set_is_valid(valid);
exports.tx_new = body => witness_set => auxiliary_data => CSL.Transaction.new(body, witness_set, auxiliary_data);

// TransactionBodies
exports.txBodies_free = self => () => self.free();
exports.txBodies_toBytes = self => self.to_bytes();
exports.txBodies_fromBytes = bytes => errorableToPurs(CSL.TransactionBodies.from_bytes, bytes);
exports.txBodies_toHex = self => self.to_hex();
exports.txBodies_fromHex = hex_str => errorableToPurs(CSL.TransactionBodies.from_hex, hex_str);
exports.txBodies_toJson = self => self.to_json();
exports.txBodies_toJsValue = self => self.to_js_value();
exports.txBodies_fromJson = json => errorableToPurs(CSL.TransactionBodies.from_json, json);
exports.txBodies_new = () => CSL.TransactionBodies.new();
exports.txBodies_len = self => () => self.len();
exports.txBodies_get = self => index => () => self.get(index);
exports.txBodies_add = self => elem => () => self.add(elem);

// TransactionBody
exports.txBody_free = self => () => self.free();
exports.txBody_toBytes = self => self.to_bytes();
exports.txBody_fromBytes = bytes => errorableToPurs(CSL.TransactionBody.from_bytes, bytes);
exports.txBody_toHex = self => self.to_hex();
exports.txBody_fromHex = hex_str => errorableToPurs(CSL.TransactionBody.from_hex, hex_str);
exports.txBody_toJson = self => self.to_json();
exports.txBody_toJsValue = self => self.to_js_value();
exports.txBody_fromJson = json => errorableToPurs(CSL.TransactionBody.from_json, json);
exports.txBody_ins = self => self.inputs();
exports.txBody_outs = self => self.outputs();
exports.txBody_fee = self => self.fee();
exports.txBody_ttl = self => self.ttl();
exports.txBody_ttlBignum = self => self.ttl_bignum();
exports.txBody_setTtl = self => ttl => () => self.set_ttl(ttl);
exports.txBody_removeTtl = self => () => self.remove_ttl();
exports.txBody_setCerts = self => certs => () => self.set_certs(certs);
exports.txBody_certs = self => self.certs();
exports.txBody_setWithdrawals = self => withdrawals => () => self.set_withdrawals(withdrawals);
exports.txBody_withdrawals = self => self.withdrawals();
exports.txBody_setUpdate = self => update => () => self.set_update(update);
exports.txBody_update = self => self.update();
exports.txBody_setAuxiliaryDataHash = self => auxiliary_data_hash => () => self.set_auxiliary_data_hash(auxiliary_data_hash);
exports.txBody_auxiliaryDataHash = self => self.auxiliary_data_hash();
exports.txBody_setValidityStartInterval = self => validity_start_interval => () => self.set_validity_start_interval(validity_start_interval);
exports.txBody_setValidityStartIntervalBignum = self => validity_start_interval => () => self.set_validity_start_interval_bignum(validity_start_interval);
exports.txBody_validityStartIntervalBignum = self => self.validity_start_interval_bignum();
exports.txBody_validityStartInterval = self => self.validity_start_interval();
exports.txBody_setMint = self => mint => () => self.set_mint(mint);
exports.txBody_mint = self => self.mint();
exports.txBody_multiassets = self => self.multiassets();
exports.txBody_setReferenceIns = self => reference_inputs => () => self.set_reference_inputs(reference_inputs);
exports.txBody_referenceIns = self => self.reference_inputs();
exports.txBody_setScriptDataHash = self => script_data_hash => () => self.set_script_data_hash(script_data_hash);
exports.txBody_scriptDataHash = self => self.script_data_hash();
exports.txBody_setCollateral = self => collateral => () => self.set_collateral(collateral);
exports.txBody_collateral = self => self.collateral();
exports.txBody_setRequiredSigners = self => required_signers => () => self.set_required_signers(required_signers);
exports.txBody_requiredSigners = self => self.required_signers();
exports.txBody_setNetworkId = self => network_id => () => self.set_network_id(network_id);
exports.txBody_networkId = self => self.network_id();
exports.txBody_setCollateralReturn = self => collateral_return => () => self.set_collateral_return(collateral_return);
exports.txBody_collateralReturn = self => self.collateral_return();
exports.txBody_setTotalCollateral = self => total_collateral => () => self.set_total_collateral(total_collateral);
exports.txBody_totalCollateral = self => self.total_collateral();
exports.txBody_new = inputs => outputs => fee => ttl => CSL.TransactionBody.new(inputs, outputs, fee, ttl);
exports.txBody_newTxBody = inputs => outputs => fee => CSL.TransactionBody.new_tx_body(inputs, outputs, fee);

// TransactionBuilder
exports.txBuilder_free = self => () => self.free();
exports.txBuilder_addInsFrom = self => inputs => strategy => () => self.add_inputs_from(inputs, strategy);
exports.txBuilder_setIns = self => inputs => () => self.set_inputs(inputs);
exports.txBuilder_setCollateral = self => collateral => () => self.set_collateral(collateral);
exports.txBuilder_setCollateralReturn = self => collateral_return => () => self.set_collateral_return(collateral_return);
exports.txBuilder_setCollateralReturnAndTotal = self => collateral_return => () => self.set_collateral_return_and_total(collateral_return);
exports.txBuilder_setTotalCollateral = self => total_collateral => () => self.set_total_collateral(total_collateral);
exports.txBuilder_setTotalCollateralAndReturn = self => total_collateral => return_address => () => self.set_total_collateral_and_return(total_collateral, return_address);
exports.txBuilder_addReferenceIn = self => reference_input => () => self.add_reference_input(reference_input);
exports.txBuilder_addKeyIn = self => hash => input => amount => () => self.add_key_input(hash, input, amount);
exports.txBuilder_addScriptIn = self => hash => input => amount => () => self.add_script_input(hash, input, amount);
exports.txBuilder_addNativeScriptIn = self => script => input => amount => () => self.add_native_script_input(script, input, amount);
exports.txBuilder_addPlutusScriptIn = self => witness => input => amount => () => self.add_plutus_script_input(witness, input, amount);
exports.txBuilder_addBootstrapIn = self => hash => input => amount => () => self.add_bootstrap_input(hash, input, amount);
exports.txBuilder_addIn = self => address => input => amount => () => self.add_input(address, input, amount);
exports.txBuilder_countMissingInScripts = self => () => self.count_missing_input_scripts();
exports.txBuilder_addRequiredNativeInScripts = self => scripts => () => self.add_required_native_input_scripts(scripts);
exports.txBuilder_addRequiredPlutusInScripts = self => scripts => () => self.add_required_plutus_input_scripts(scripts);
exports.txBuilder_getNativeInScripts = self => () => self.get_native_input_scripts();
exports.txBuilder_getPlutusInScripts = self => () => self.get_plutus_input_scripts();
exports.txBuilder_feeForIn = self => address => input => amount => () => self.fee_for_input(address, input, amount);
exports.txBuilder_addOut = self => output => () => self.add_output(output);
exports.txBuilder_feeForOut = self => output => () => self.fee_for_output(output);
exports.txBuilder_setFee = self => fee => () => self.set_fee(fee);
exports.txBuilder_setTtl = self => ttl => () => self.set_ttl(ttl);
exports.txBuilder_setTtlBignum = self => ttl => () => self.set_ttl_bignum(ttl);
exports.txBuilder_setValidityStartInterval = self => validity_start_interval => () => self.set_validity_start_interval(validity_start_interval);
exports.txBuilder_setValidityStartIntervalBignum = self => validity_start_interval => () => self.set_validity_start_interval_bignum(validity_start_interval);
exports.txBuilder_setCerts = self => certs => () => self.set_certs(certs);
exports.txBuilder_setWithdrawals = self => withdrawals => () => self.set_withdrawals(withdrawals);
exports.txBuilder_getAuxiliaryData = self => () => self.get_auxiliary_data();
exports.txBuilder_setAuxiliaryData = self => auxiliary_data => () => self.set_auxiliary_data(auxiliary_data);
exports.txBuilder_setMetadata = self => metadata => () => self.set_metadata(metadata);
exports.txBuilder_addMetadatum = self => key => val => () => self.add_metadatum(key, val);
exports.txBuilder_addJsonMetadatum = self => key => val => () => self.add_json_metadatum(key, val);
exports.txBuilder_addJsonMetadatumWithSchema = self => key => val => schema => () => self.add_json_metadatum_with_schema(key, val, schema);
exports.txBuilder_setMint = self => mint => mint_scripts => () => self.set_mint(mint, mint_scripts);
exports.txBuilder_getMint = self => () => self.get_mint();
exports.txBuilder_getMintScripts = self => () => self.get_mint_scripts();
exports.txBuilder_setMintAsset = self => policy_script => mint_assets => () => self.set_mint_asset(policy_script, mint_assets);
exports.txBuilder_addMintAsset = self => policy_script => asset_name => amount => () => self.add_mint_asset(policy_script, asset_name, amount);
exports.txBuilder_addMintAssetAndOut = self => policy_script => asset_name => amount => output_builder => output_coin => () => self.add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin);
exports.txBuilder_addMintAssetAndOutMinRequiredCoin = self => policy_script => asset_name => amount => output_builder => () => self.add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder);
exports.txBuilder_new = cfg => () => CSL.TransactionBuilder.new(cfg);
exports.txBuilder_getReferenceIns = self => () => self.get_reference_inputs();
exports.txBuilder_getExplicitIn = self => () => self.get_explicit_input();
exports.txBuilder_getImplicitIn = self => () => self.get_implicit_input();
exports.txBuilder_getTotalIn = self => () => self.get_total_input();
exports.txBuilder_getTotalOut = self => () => self.get_total_output();
exports.txBuilder_getExplicitOut = self => () => self.get_explicit_output();
exports.txBuilder_getDeposit = self => () => self.get_deposit();
exports.txBuilder_getFeeIfSet = self => () => self.get_fee_if_set();
exports.txBuilder_addChangeIfNeeded = self => address => () => self.add_change_if_needed(address);
exports.txBuilder_calcScriptDataHash = self => cost_models => () => self.calc_script_data_hash(cost_models);
exports.txBuilder_setScriptDataHash = self => hash => () => self.set_script_data_hash(hash);
exports.txBuilder_removeScriptDataHash = self => () => self.remove_script_data_hash();
exports.txBuilder_addRequiredSigner = self => key => () => self.add_required_signer(key);
exports.txBuilder_fullSize = self => () => self.full_size();
exports.txBuilder_outSizes = self => () => self.output_sizes();
exports.txBuilder_build = self => () => self.build();
exports.txBuilder_buildTx = self => () => self.build_tx();
exports.txBuilder_buildTxUnsafe = self => () => self.build_tx_unsafe();
exports.txBuilder_minFee = self => () => self.min_fee();

// TransactionBuilderConfig
exports.txBuilderConfig_free = self => () => self.free();

// TransactionBuilderConfigBuilder
exports.txBuilderConfigBuilder_free = self => () => self.free();
exports.txBuilderConfigBuilder_new = CSL.TransactionBuilderConfigBuilder.new();
exports.txBuilderConfigBuilder_feeAlgo = self => fee_algo => self.fee_algo(fee_algo);
exports.txBuilderConfigBuilder_coinsPerUtxoWord = self => coins_per_utxo_word => self.coins_per_utxo_word(coins_per_utxo_word);
exports.txBuilderConfigBuilder_coinsPerUtxoByte = self => coins_per_utxo_byte => self.coins_per_utxo_byte(coins_per_utxo_byte);
exports.txBuilderConfigBuilder_exUnitPrices = self => ex_unit_prices => self.ex_unit_prices(ex_unit_prices);
exports.txBuilderConfigBuilder_poolDeposit = self => pool_deposit => self.pool_deposit(pool_deposit);
exports.txBuilderConfigBuilder_keyDeposit = self => key_deposit => self.key_deposit(key_deposit);
exports.txBuilderConfigBuilder_maxValueSize = self => max_value_size => self.max_value_size(max_value_size);
exports.txBuilderConfigBuilder_maxTxSize = self => max_tx_size => self.max_tx_size(max_tx_size);
exports.txBuilderConfigBuilder_preferPureChange = self => prefer_pure_change => self.prefer_pure_change(prefer_pure_change);
exports.txBuilderConfigBuilder_build = self => self.build();

// TransactionHash
exports.txHash_free = self => () => self.free();
exports.txHash_fromBytes = bytes => errorableToPurs(CSL.TransactionHash.from_bytes, bytes);
exports.txHash_toBytes = self => self.to_bytes();
exports.txHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.txHash_fromBech32 = bech_str => errorableToPurs(CSL.TransactionHash.from_bech32, bech_str);
exports.txHash_toHex = self => self.to_hex();
exports.txHash_fromHex = hex => errorableToPurs(CSL.TransactionHash.from_hex, hex);

// TransactionInput
exports.txIn_free = self => () => self.free();
exports.txIn_toBytes = self => self.to_bytes();
exports.txIn_fromBytes = bytes => errorableToPurs(CSL.TransactionInput.from_bytes, bytes);
exports.txIn_toHex = self => self.to_hex();
exports.txIn_fromHex = hex_str => errorableToPurs(CSL.TransactionInput.from_hex, hex_str);
exports.txIn_toJson = self => self.to_json();
exports.txIn_toJsValue = self => self.to_js_value();
exports.txIn_fromJson = json => errorableToPurs(CSL.TransactionInput.from_json, json);
exports.txIn_txId = self => self.transaction_id();
exports.txIn_index = self => self.index();
exports.txIn_new = transaction_id => index => CSL.TransactionInput.new(transaction_id, index);

// TransactionInputs
exports.txIns_free = self => () => self.free();
exports.txIns_toBytes = self => self.to_bytes();
exports.txIns_fromBytes = bytes => errorableToPurs(CSL.TransactionInputs.from_bytes, bytes);
exports.txIns_toHex = self => self.to_hex();
exports.txIns_fromHex = hex_str => errorableToPurs(CSL.TransactionInputs.from_hex, hex_str);
exports.txIns_toJson = self => self.to_json();
exports.txIns_toJsValue = self => self.to_js_value();
exports.txIns_fromJson = json => errorableToPurs(CSL.TransactionInputs.from_json, json);
exports.txIns_new = () => CSL.TransactionInputs.new();
exports.txIns_len = self => () => self.len();
exports.txIns_get = self => index => () => self.get(index);
exports.txIns_add = self => elem => () => self.add(elem);
exports.txIns_toOption = self => self.to_option();

// TransactionMetadatum
exports.txMetadatum_free = self => () => self.free();
exports.txMetadatum_toBytes = self => self.to_bytes();
exports.txMetadatum_fromBytes = bytes => errorableToPurs(CSL.TransactionMetadatum.from_bytes, bytes);
exports.txMetadatum_toHex = self => self.to_hex();
exports.txMetadatum_fromHex = hex_str => errorableToPurs(CSL.TransactionMetadatum.from_hex, hex_str);
exports.txMetadatum_newMap = map => CSL.TransactionMetadatum.new_map(map);
exports.txMetadatum_newList = list => CSL.TransactionMetadatum.new_list(list);
exports.txMetadatum_newInt = int => CSL.TransactionMetadatum.new_int(int);
exports.txMetadatum_newBytes = bytes => CSL.TransactionMetadatum.new_bytes(bytes);
exports.txMetadatum_newText = text => CSL.TransactionMetadatum.new_text(text);
exports.txMetadatum_kind = self => self.kind();
exports.txMetadatum_asMap = self => self.as_map();
exports.txMetadatum_asList = self => self.as_list();
exports.txMetadatum_asInt = self => self.as_int();
exports.txMetadatum_asBytes = self => self.as_bytes();
exports.txMetadatum_asText = self => self.as_text();

// TransactionMetadatumLabels
exports.txMetadatumLabels_free = self => () => self.free();
exports.txMetadatumLabels_toBytes = self => self.to_bytes();
exports.txMetadatumLabels_fromBytes = bytes => errorableToPurs(CSL.TransactionMetadatumLabels.from_bytes, bytes);
exports.txMetadatumLabels_toHex = self => self.to_hex();
exports.txMetadatumLabels_fromHex = hex_str => errorableToPurs(CSL.TransactionMetadatumLabels.from_hex, hex_str);
exports.txMetadatumLabels_new = () => CSL.TransactionMetadatumLabels.new();
exports.txMetadatumLabels_len = self => () => self.len();
exports.txMetadatumLabels_get = self => index => () => self.get(index);
exports.txMetadatumLabels_add = self => elem => () => self.add(elem);

// TransactionOutput
exports.txOut_free = self => () => self.free();
exports.txOut_toBytes = self => self.to_bytes();
exports.txOut_fromBytes = bytes => errorableToPurs(CSL.TransactionOutput.from_bytes, bytes);
exports.txOut_toHex = self => self.to_hex();
exports.txOut_fromHex = hex_str => errorableToPurs(CSL.TransactionOutput.from_hex, hex_str);
exports.txOut_toJson = self => self.to_json();
exports.txOut_toJsValue = self => self.to_js_value();
exports.txOut_fromJson = json => errorableToPurs(CSL.TransactionOutput.from_json, json);
exports.txOut_address = self => self.address();
exports.txOut_amount = self => self.amount();
exports.txOut_dataHash = self => self.data_hash();
exports.txOut_plutusData = self => self.plutus_data();
exports.txOut_scriptRef = self => self.script_ref();
exports.txOut_setScriptRef = self => script_ref => () => self.set_script_ref(script_ref);
exports.txOut_setPlutusData = self => data => () => self.set_plutus_data(data);
exports.txOut_setDataHash = self => data_hash => () => self.set_data_hash(data_hash);
exports.txOut_hasPlutusData = self => self.has_plutus_data();
exports.txOut_hasDataHash = self => self.has_data_hash();
exports.txOut_hasScriptRef = self => self.has_script_ref();
exports.txOut_new = address => amount => CSL.TransactionOutput.new(address, amount);

// TransactionOutputAmountBuilder
exports.txOutAmountBuilder_free = self => () => self.free();
exports.txOutAmountBuilder_withValue = self => amount => self.with_value(amount);
exports.txOutAmountBuilder_withCoin = self => coin => self.with_coin(coin);
exports.txOutAmountBuilder_withCoinAndAsset = self => coin => multiasset => self.with_coin_and_asset(coin, multiasset);
exports.txOutAmountBuilder_withAssetAndMinRequiredCoin = self => multiasset => coins_per_utxo_word => self.with_asset_and_min_required_coin(multiasset, coins_per_utxo_word);
exports.txOutAmountBuilder_withAssetAndMinRequiredCoinByUtxoCost = self => multiasset => data_cost => self.with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost);
exports.txOutAmountBuilder_build = self => self.build();

// TransactionOutputBuilder
exports.txOutBuilder_free = self => () => self.free();
exports.txOutBuilder_new = CSL.TransactionOutputBuilder.new();
exports.txOutBuilder_withAddress = self => address => self.with_address(address);
exports.txOutBuilder_withDataHash = self => data_hash => self.with_data_hash(data_hash);
exports.txOutBuilder_withPlutusData = self => data => self.with_plutus_data(data);
exports.txOutBuilder_withScriptRef = self => script_ref => self.with_script_ref(script_ref);
exports.txOutBuilder_next = self => self.next();

// TransactionOutputs
exports.txOuts_free = self => () => self.free();
exports.txOuts_toBytes = self => self.to_bytes();
exports.txOuts_fromBytes = bytes => errorableToPurs(CSL.TransactionOutputs.from_bytes, bytes);
exports.txOuts_toHex = self => self.to_hex();
exports.txOuts_fromHex = hex_str => errorableToPurs(CSL.TransactionOutputs.from_hex, hex_str);
exports.txOuts_toJson = self => self.to_json();
exports.txOuts_toJsValue = self => self.to_js_value();
exports.txOuts_fromJson = json => errorableToPurs(CSL.TransactionOutputs.from_json, json);
exports.txOuts_new = () => CSL.TransactionOutputs.new();
exports.txOuts_len = self => () => self.len();
exports.txOuts_get = self => index => () => self.get(index);
exports.txOuts_add = self => elem => () => self.add(elem);

// TransactionUnspentOutput
exports.txUnspentOut_free = self => () => self.free();
exports.txUnspentOut_toBytes = self => self.to_bytes();
exports.txUnspentOut_fromBytes = bytes => errorableToPurs(CSL.TransactionUnspentOutput.from_bytes, bytes);
exports.txUnspentOut_toHex = self => self.to_hex();
exports.txUnspentOut_fromHex = hex_str => errorableToPurs(CSL.TransactionUnspentOutput.from_hex, hex_str);
exports.txUnspentOut_toJson = self => self.to_json();
exports.txUnspentOut_toJsValue = self => self.to_js_value();
exports.txUnspentOut_fromJson = json => errorableToPurs(CSL.TransactionUnspentOutput.from_json, json);
exports.txUnspentOut_new = input => output => CSL.TransactionUnspentOutput.new(input, output);
exports.txUnspentOut_in = self => self.input();
exports.txUnspentOut_out = self => self.output();

// TransactionUnspentOutputs
exports.txUnspentOuts_free = self => () => self.free();
exports.txUnspentOuts_toJson = self => self.to_json();
exports.txUnspentOuts_toJsValue = self => self.to_js_value();
exports.txUnspentOuts_fromJson = json => errorableToPurs(CSL.TransactionUnspentOutputs.from_json, json);
exports.txUnspentOuts_new = () => CSL.TransactionUnspentOutputs.new();
exports.txUnspentOuts_len = self => () => self.len();
exports.txUnspentOuts_get = self => index => () => self.get(index);
exports.txUnspentOuts_add = self => elem => () => self.add(elem);

// TransactionWitnessSet
exports.txWitnessSet_free = self => () => self.free();
exports.txWitnessSet_toBytes = self => self.to_bytes();
exports.txWitnessSet_fromBytes = bytes => errorableToPurs(CSL.TransactionWitnessSet.from_bytes, bytes);
exports.txWitnessSet_toHex = self => self.to_hex();
exports.txWitnessSet_fromHex = hex_str => errorableToPurs(CSL.TransactionWitnessSet.from_hex, hex_str);
exports.txWitnessSet_toJson = self => self.to_json();
exports.txWitnessSet_toJsValue = self => self.to_js_value();
exports.txWitnessSet_fromJson = json => errorableToPurs(CSL.TransactionWitnessSet.from_json, json);
exports.txWitnessSet_setVkeys = self => vkeys => () => self.set_vkeys(vkeys);
exports.txWitnessSet_vkeys = self => () => self.vkeys();
exports.txWitnessSet_setNativeScripts = self => native_scripts => () => self.set_native_scripts(native_scripts);
exports.txWitnessSet_nativeScripts = self => () => self.native_scripts();
exports.txWitnessSet_setBootstraps = self => bootstraps => () => self.set_bootstraps(bootstraps);
exports.txWitnessSet_bootstraps = self => () => self.bootstraps();
exports.txWitnessSet_setPlutusScripts = self => plutus_scripts => () => self.set_plutus_scripts(plutus_scripts);
exports.txWitnessSet_plutusScripts = self => () => self.plutus_scripts();
exports.txWitnessSet_setPlutusData = self => plutus_data => () => self.set_plutus_data(plutus_data);
exports.txWitnessSet_plutusData = self => () => self.plutus_data();
exports.txWitnessSet_setRedeemers = self => redeemers => () => self.set_redeemers(redeemers);
exports.txWitnessSet_redeemers = self => () => self.redeemers();
exports.txWitnessSet_new = () => CSL.TransactionWitnessSet.new();

// TransactionWitnessSets
exports.txWitnessSets_free = self => () => self.free();
exports.txWitnessSets_toBytes = self => self.to_bytes();
exports.txWitnessSets_fromBytes = bytes => errorableToPurs(CSL.TransactionWitnessSets.from_bytes, bytes);
exports.txWitnessSets_toHex = self => self.to_hex();
exports.txWitnessSets_fromHex = hex_str => errorableToPurs(CSL.TransactionWitnessSets.from_hex, hex_str);
exports.txWitnessSets_toJson = self => self.to_json();
exports.txWitnessSets_toJsValue = self => self.to_js_value();
exports.txWitnessSets_fromJson = json => errorableToPurs(CSL.TransactionWitnessSets.from_json, json);
exports.txWitnessSets_new = () => CSL.TransactionWitnessSets.new();
exports.txWitnessSets_len = self => () => self.len();
exports.txWitnessSets_get = self => index => () => self.get(index);
exports.txWitnessSets_add = self => elem => () => self.add(elem);

// TxBuilderConstants
exports.txBuilderConstants_free = self => () => self.free();
exports.txBuilderConstants_plutusDefaultCostModels = CSL.TxBuilderConstants.plutus_default_cost_models();
exports.txBuilderConstants_plutusAlonzoCostModels = CSL.TxBuilderConstants.plutus_alonzo_cost_models();
exports.txBuilderConstants_plutusVasilCostModels = CSL.TxBuilderConstants.plutus_vasil_cost_models();

// TxInputsBuilder
exports.txInsBuilder_free = self => () => self.free();
exports.txInsBuilder_new = () => CSL.TxInputsBuilder.new();
exports.txInsBuilder_addKeyIn = self => hash => input => amount => () => self.add_key_input(hash, input, amount);
exports.txInsBuilder_addScriptIn = self => hash => input => amount => () => self.add_script_input(hash, input, amount);
exports.txInsBuilder_addNativeScriptIn = self => script => input => amount => () => self.add_native_script_input(script, input, amount);
exports.txInsBuilder_addPlutusScriptIn = self => witness => input => amount => () => self.add_plutus_script_input(witness, input, amount);
exports.txInsBuilder_addBootstrapIn = self => hash => input => amount => () => self.add_bootstrap_input(hash, input, amount);
exports.txInsBuilder_addIn = self => address => input => amount => () => self.add_input(address, input, amount);
exports.txInsBuilder_countMissingInScripts = self => () => self.count_missing_input_scripts();
exports.txInsBuilder_addRequiredNativeInScripts = self => scripts => () => self.add_required_native_input_scripts(scripts);
exports.txInsBuilder_addRequiredPlutusInScripts = self => scripts => () => self.add_required_plutus_input_scripts(scripts);
exports.txInsBuilder_getRefIns = self => () => self.get_ref_inputs();
exports.txInsBuilder_getNativeInScripts = self => () => self.get_native_input_scripts();
exports.txInsBuilder_getPlutusInScripts = self => () => self.get_plutus_input_scripts();
exports.txInsBuilder_len = self => () => self.len();
exports.txInsBuilder_addRequiredSigner = self => key => () => self.add_required_signer(key);
exports.txInsBuilder_addRequiredSigners = self => keys => () => self.add_required_signers(keys);
exports.txInsBuilder_totalValue = self => () => self.total_value();
exports.txInsBuilder_ins = self => () => self.inputs();
exports.txInsBuilder_insOption = self => () => self.inputs_option();

// URL
exports.url_free = self => () => self.free();
exports.url_toBytes = self => self.to_bytes();
exports.url_fromBytes = bytes => errorableToPurs(CSL.URL.from_bytes, bytes);
exports.url_toHex = self => self.to_hex();
exports.url_fromHex = hex_str => errorableToPurs(CSL.URL.from_hex, hex_str);
exports.url_toJson = self => self.to_json();
exports.url_toJsValue = self => self.to_js_value();
exports.url_fromJson = json => errorableToPurs(CSL.URL.from_json, json);
exports.url_new = url => CSL.URL.new(url);
exports.url_url = self => self.url();

// UnitInterval
exports.unitInterval_free = self => () => self.free();
exports.unitInterval_toBytes = self => self.to_bytes();
exports.unitInterval_fromBytes = bytes => errorableToPurs(CSL.UnitInterval.from_bytes, bytes);
exports.unitInterval_toHex = self => self.to_hex();
exports.unitInterval_fromHex = hex_str => errorableToPurs(CSL.UnitInterval.from_hex, hex_str);
exports.unitInterval_toJson = self => self.to_json();
exports.unitInterval_toJsValue = self => self.to_js_value();
exports.unitInterval_fromJson = json => errorableToPurs(CSL.UnitInterval.from_json, json);
exports.unitInterval_numerator = self => self.numerator();
exports.unitInterval_denominator = self => self.denominator();
exports.unitInterval_new = numerator => denominator => CSL.UnitInterval.new(numerator, denominator);

// Update
exports.update_free = self => () => self.free();
exports.update_toBytes = self => self.to_bytes();
exports.update_fromBytes = bytes => errorableToPurs(CSL.Update.from_bytes, bytes);
exports.update_toHex = self => self.to_hex();
exports.update_fromHex = hex_str => errorableToPurs(CSL.Update.from_hex, hex_str);
exports.update_toJson = self => self.to_json();
exports.update_toJsValue = self => self.to_js_value();
exports.update_fromJson = json => errorableToPurs(CSL.Update.from_json, json);
exports.update_proposedProtocolParameterUpdates = self => self.proposed_protocol_parameter_updates();
exports.update_epoch = self => self.epoch();
exports.update_new = proposed_protocol_parameter_updates => epoch => CSL.Update.new(proposed_protocol_parameter_updates, epoch);

// VRFCert
exports.vrfCert_free = self => () => self.free();
exports.vrfCert_toBytes = self => self.to_bytes();
exports.vrfCert_fromBytes = bytes => errorableToPurs(CSL.VRFCert.from_bytes, bytes);
exports.vrfCert_toHex = self => self.to_hex();
exports.vrfCert_fromHex = hex_str => errorableToPurs(CSL.VRFCert.from_hex, hex_str);
exports.vrfCert_toJson = self => self.to_json();
exports.vrfCert_toJsValue = self => self.to_js_value();
exports.vrfCert_fromJson = json => errorableToPurs(CSL.VRFCert.from_json, json);
exports.vrfCert_out = self => self.output();
exports.vrfCert_proof = self => self.proof();
exports.vrfCert_new = output => proof => CSL.VRFCert.new(output, proof);

// VRFKeyHash
exports.vrfKeyHash_free = self => () => self.free();
exports.vrfKeyHash_fromBytes = bytes => errorableToPurs(CSL.VRFKeyHash.from_bytes, bytes);
exports.vrfKeyHash_toBytes = self => self.to_bytes();
exports.vrfKeyHash_toBech32 = self => prefix => self.to_bech32(prefix);
exports.vrfKeyHash_fromBech32 = bech_str => errorableToPurs(CSL.VRFKeyHash.from_bech32, bech_str);
exports.vrfKeyHash_toHex = self => self.to_hex();
exports.vrfKeyHash_fromHex = hex => errorableToPurs(CSL.VRFKeyHash.from_hex, hex);

// VRFVKey
exports.vrfvKey_free = self => () => self.free();
exports.vrfvKey_fromBytes = bytes => errorableToPurs(CSL.VRFVKey.from_bytes, bytes);
exports.vrfvKey_toBytes = self => self.to_bytes();
exports.vrfvKey_toBech32 = self => prefix => self.to_bech32(prefix);
exports.vrfvKey_fromBech32 = bech_str => errorableToPurs(CSL.VRFVKey.from_bech32, bech_str);
exports.vrfvKey_toHex = self => self.to_hex();
exports.vrfvKey_fromHex = hex => errorableToPurs(CSL.VRFVKey.from_hex, hex);

// Value
exports.value_free = self => () => self.free();
exports.value_toBytes = self => self.to_bytes();
exports.value_fromBytes = bytes => errorableToPurs(CSL.Value.from_bytes, bytes);
exports.value_toHex = self => self.to_hex();
exports.value_fromHex = hex_str => errorableToPurs(CSL.Value.from_hex, hex_str);
exports.value_toJson = self => self.to_json();
exports.value_toJsValue = self => self.to_js_value();
exports.value_fromJson = json => errorableToPurs(CSL.Value.from_json, json);
exports.value_new = coin => CSL.Value.new(coin);
exports.value_newFromAssets = multiasset => CSL.Value.new_from_assets(multiasset);
exports.value_newWithAssets = coin => multiasset => CSL.Value.new_with_assets(coin, multiasset);
exports.value_zero = CSL.Value.zero();
exports.value_isZero = self => self.is_zero();
exports.value_coin = self => self.coin();
exports.value_setCoin = self => coin => () => self.set_coin(coin);
exports.value_multiasset = self => self.multiasset();
exports.value_setMultiasset = self => multiasset => () => self.set_multiasset(multiasset);
exports.value_checkedAdd = self => rhs => self.checked_add(rhs);
exports.value_checkedSub = self => rhs_value => self.checked_sub(rhs_value);
exports.value_clampedSub = self => rhs_value => self.clamped_sub(rhs_value);
exports.value_compare = self => rhs_value => self.compare(rhs_value);

// Vkey
exports.vkey_free = self => () => self.free();
exports.vkey_toBytes = self => self.to_bytes();
exports.vkey_fromBytes = bytes => errorableToPurs(CSL.Vkey.from_bytes, bytes);
exports.vkey_toHex = self => self.to_hex();
exports.vkey_fromHex = hex_str => errorableToPurs(CSL.Vkey.from_hex, hex_str);
exports.vkey_toJson = self => self.to_json();
exports.vkey_toJsValue = self => self.to_js_value();
exports.vkey_fromJson = json => errorableToPurs(CSL.Vkey.from_json, json);
exports.vkey_new = pk => CSL.Vkey.new(pk);
exports.vkey_publicKey = self => self.public_key();

// Vkeys
exports.vkeys_free = self => () => self.free();
exports.vkeys_new = () => CSL.Vkeys.new();
exports.vkeys_len = self => () => self.len();
exports.vkeys_get = self => index => () => self.get(index);
exports.vkeys_add = self => elem => () => self.add(elem);

// Vkeywitness
exports.vkeywitness_free = self => () => self.free();
exports.vkeywitness_toBytes = self => self.to_bytes();
exports.vkeywitness_fromBytes = bytes => errorableToPurs(CSL.Vkeywitness.from_bytes, bytes);
exports.vkeywitness_toHex = self => self.to_hex();
exports.vkeywitness_fromHex = hex_str => errorableToPurs(CSL.Vkeywitness.from_hex, hex_str);
exports.vkeywitness_toJson = self => self.to_json();
exports.vkeywitness_toJsValue = self => self.to_js_value();
exports.vkeywitness_fromJson = json => errorableToPurs(CSL.Vkeywitness.from_json, json);
exports.vkeywitness_new = vkey => signature => CSL.Vkeywitness.new(vkey, signature);
exports.vkeywitness_vkey = self => self.vkey();
exports.vkeywitness_signature = self => self.signature();

// Vkeywitnesses
exports.vkeywitnesses_free = self => () => self.free();
exports.vkeywitnesses_new = () => CSL.Vkeywitnesses.new();
exports.vkeywitnesses_len = self => () => self.len();
exports.vkeywitnesses_get = self => index => () => self.get(index);
exports.vkeywitnesses_add = self => elem => () => self.add(elem);

// Withdrawals
exports.withdrawals_free = self => () => self.free();
exports.withdrawals_toBytes = self => self.to_bytes();
exports.withdrawals_fromBytes = bytes => errorableToPurs(CSL.Withdrawals.from_bytes, bytes);
exports.withdrawals_toHex = self => self.to_hex();
exports.withdrawals_fromHex = hex_str => errorableToPurs(CSL.Withdrawals.from_hex, hex_str);
exports.withdrawals_toJson = self => self.to_json();
exports.withdrawals_toJsValue = self => self.to_js_value();
exports.withdrawals_fromJson = json => errorableToPurs(CSL.Withdrawals.from_json, json);
exports.withdrawals_new = () => CSL.Withdrawals.new();
exports.withdrawals_len = self => () => self.len();
exports.withdrawals_insert = self => key => value => () => self.insert(key, value);
exports.withdrawals_get = self => key => () => self.get(key);
exports.withdrawals_keys = self => () => self.keys();

