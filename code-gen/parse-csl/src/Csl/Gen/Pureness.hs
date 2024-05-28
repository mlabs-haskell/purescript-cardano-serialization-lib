module Csl.Gen.Pureness (
  getPureness,
  Pureness (Pure, Mutating, Throwing),
  isPure,
) where

import Csl.Types
import Data.Set (Set)
import Data.Set qualified as Set

data Pureness = Pure | Mutating | Throwing
  deriving (Eq, Show)

getPureness :: String -> Fun -> Pureness
getPureness className Fun {..}
  | isConvertor fun'name = Pure
  | take 4 fun'name `elem` ["set_", "add_"] = Mutating
  | fun'name == "insert" = Mutating
  | fun'res == "void" = Throwing
  | isMutating && not isThrowing = Mutating
  | not isMutating && not isThrowing = Pure
  | otherwise = Throwing
  where
    isMutating = mutatingMethods (className, fun'name)
    isThrowing = Set.member (className, fun'name) throwingSet || isCommonThrowingMethod fun'name
    isConvertor a = Set.member a convertorSet

isPure :: String -> Fun -> Bool
isPure className fun =
  getPureness className fun == Pure

mutatingMethods :: (String, String) -> Bool
mutatingMethods a = Set.member a mutating

mutating :: Set (String, String)
mutating =
  mconcat $
    [ keys "Assets"
    , inClass "TransactionBuilder" ["new"]
    , inClass "TransactionWitnessSet" ["new"]
    , inClass
        "AuxiliaryData"
        ["new", "set_native_scripts", "set_plutus_scripts", "set_metadata", "set_prefer_alonzo_format"]
    , inClass "AuxiliaryDataSet" ["new", "insert", "get", "indices"]
    , newSetGet "CostModel"
    , keys "Costmdls"
    , keys "GeneralTransactionMetadata"
    , keys "MIRToStakeCredentials"
    , inClass "MetadataMap" ["new", "insert", "insert_str", "insert_i32", "get", "get_str", "get_i32", "has", "keys"]
    , keys "Mint" <> inClass "Mint" ["new_from_entry", "as_positive_multiasset", "as_negative_multiasset"]
    , keys "MintAssets"
    , inClass "MultiAsset" ["new", "len", "inset", "get", "get_asset", "set_asset", "keys", "sub"]
    , inClass "Value" ["set_multiasset"]
    , inClass "TransactionOutput" ["set_data_hash", "set_plutus_data", "set_script_ref"]
    , keys "PlutusMap"
    , inClass "PrivateKey" ["generate_ed25519", "generate_ed25519extended"]
    , keys "ProposedProtocolParameterUpdates"
    , keys "Withdrawals"
    , inClass "Committee" ["new"]
    , inClass "VotingProcedures" ["new", "get", "get_voters", "get_governance_action_ids_by_voter"]
    ]
      ++ map (list . fst) listTypes
  where
    inClass name ms = Set.fromList $ fmap (name,) ms
    list name = inClass name ["new", "get", "add", "len"]
    newSetGet name = inClass name ["new", "set", "get", "len"]
    keys name = inClass name ["new", "insert", "get", "keys", "len"]

throwingSet :: Set (String, String)
throwingSet =
  mconcat
    [ inClass
        "BigNum"
        [ "checked_mul"
        , "checked_add"
        , "checked_sub"
        ]
    , inClass
        "Value"
        [ "checked_add"
        , "checked_sub"
        ]
    , inClass
        "PublicKey"
        ["from_bytes"]
    , inClass
        "PrivateKey"
        ["from_normal_bytes"]
    , inClass
        "ByronAddress"
        ["from_base58"]
    , inClass
        "TransactionMetadatum"
        ["as_map", "as_list", "as_int", "as_bytes", "as_text"]
    ]
  where
    inClass name ms = Set.fromList $ fmap (name,) ms

listTypes :: [(String, String)]
listTypes =
  [ ("AssetNames", "AssetName")
  , ("BootstrapWitnesses", "BootstrapWitness")
  , ("Certificates", "Certificate")
  , ("GenesisHashes", "GenesisHash")
  , ("Languages", "Language")
  , ("MetadataList", "TransactionMetadatum")
  , ("NativeScripts", "NativeScript")
  , ("PlutusList", "PlutusData")
  , ("PlutusScripts", "PlutusScript")
  , ("PlutusWitnesses", "PlutusWitness")
  , ("Redeemers", "Redeemer")
  , ("Relays", "Relay")
  , ("RewardAddresses", "RewardAddress")
  , ("ScriptHashes", "ScriptHash")
  , ("StakeCredentials", "StakeCredential")
  , ("Strings", "String")
  , ("TransactionBodies", "TransactionBody")
  , ("TransactionInputs", "TransactionInput")
  , ("TransactionOutputs", "TransactionOutput")
  , ("TransactionUnspentOutputs", "TransactionUnspentOutput")
  , ("TransactionMetadatumLabels", "BigNum")
  , ("Vkeys", "Vkey")
  , ("Vkeywitnesses", "Vkeywitness")
  ]

convertorSet :: Set String
convertorSet =
  Set.fromList $
    (\x -> fmap (<> x) ["to_"])
      =<< ["hex", "string", "bytes", "bech32", "json", "js_value"]

{- | Is function pure and can throw (in this case we can catch it to Maybe on purs side)
if it's global function use empty name for class
-}
isCommonThrowingMethod :: String -> Bool
isCommonThrowingMethod method = Set.member method froms
  where
    froms =
      Set.fromList
        [ "from_hex"
        , "from_bytes"
        , "from_normal_bytes"
        , "from_extended_bytes"
        , "from_bech32"
        , "from_json"
        , "from_str"
        ]
