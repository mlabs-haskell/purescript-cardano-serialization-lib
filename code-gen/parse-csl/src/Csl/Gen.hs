module Csl.Gen
  ( exportListPurs
  , classJs
  , classPurs
  , funPurs
  , enumPurs
  , isCommon
  , funJs
  , getPureness
  ) where

import Control.Monad (guard)
import Data.Char (isUpper, toLower)
import Data.Map (Map)
import Data.Map qualified as Map
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Functor ((<&>))
import Data.List qualified as L (intercalate, sort, nub, null, foldl', isPrefixOf, isSuffixOf)
import Data.List.Extra qualified as L (stripSuffix)
import Data.List.Split (splitOn)
import Data.Maybe (fromMaybe, mapMaybe, listToMaybe, catMaybes)
import Data.Text qualified as T (pack, unpack, replace)
import Data.Text (Text)
import Data.Text.Manipulate qualified as T (toCamel, upperHead, lowerHead, toTitle)
import Data.List.Extra (dropPrefix, trim)
import Csl.Types

exportListPurs :: [Fun] -> [Class] -> [CslEnum] -> String
exportListPurs funs cls enums =
  L.intercalate "\n  , " $
  extraExport ++
  (classMethods =<< cls) ++
  (toName . fun'name <$> funs) ++
  (fromType =<< classTypes cls) ++
  (enum'name <$> enums) ++
  ((\x -> enumName x <> "(..)") <$> enums)
  where
    fromType ty = [ty]

    extraExport :: [String]
    extraExport =
      [ "module X"
      ]

classMethods :: Class -> [String]
classMethods cls@(Class name _ms) =
  map (mappend (toTypePrefix name <> "_") . toName . fun'name . method'fun)
  $ filterMethods cls

-- Remove standard types and transform case
postProcTypes :: [String] -> [String]
postProcTypes = filter (not . flip Set.member standardTypes) . fmap toType . L.sort . L.nub
  where
    standardTypes :: Set String
    standardTypes = Set.fromList
      [ "String"
      , "Boolean"
      , "Effect"
      , "Number"
      , "Unit"
      , "ByteArray"
      , "Uint32Array"
      , "This"
      ]

classTypes :: [Class] -> [String]
classTypes xs = postProcTypes $ fromClass =<< xs
  where
    fromClass Class{..} = [class'name]

typePurs :: String -> String
typePurs ty =
  unlines
    [ typeDefPurs ty
    ]

typeDefPurs :: String -> String
typeDefPurs ty
  | isJsonType ty = unwords [ "type", ty, "= Json"]
  | otherwise = unwords [ "foreign import data", ty, ":: Type" ]

isJsonType :: String -> Bool
isJsonType ty = L.isSuffixOf "Json" ty

funPurs :: Fun -> String
funPurs fun@(Fun name args res) =
  unlines
    [ preFunComment fun
    , unwords
        [ "foreign import"
        , funName
        , "::"
        , L.intercalate " -> " argTypeNames
        , "->"
        , toType res
        ]
    ]
  where
    funName = toName name
    argTypeNames = toType . arg'type <$> args
    preFunComment = funCommentBy preComment

    funCommentBy title f =
      L.intercalate "\n"
      [ title (funTitleComment f)
      , codeComment (funCodeComment f)
      ]

    funTitleComment Fun{..} = toTitle fun'name
    funCodeComment Fun{..} = unwords [toName fun'name, unwords argNames]
      where
        argNames = toName . arg'name <$> fun'args

codeComment :: String -> String
codeComment str = "-- > " <> str

preComment :: String -> String
preComment str = "-- | " <> str

data FunSpec = FunSpec
  { funSpec'parent    :: String
  , funSpec'skipFirst :: Bool
  , funSpec'prefix    :: String
  , funSpec'pureness  :: Pureness
  }

isListContainer :: Class -> Maybe String
isListContainer (Class _ methods) = do
  guard $ all (`elem` methodNames) [ "add", "len", "get" ]
  listToMaybe $ mapMaybe getElement methods
  where
    methodNames = fun'name . method'fun <$> methods
    getElement :: Method -> Maybe String
    getElement (Method _ (Fun "add" [Arg _ elemType] _)) = Just elemType
    getElement _ = Nothing

isMapContainer :: Class -> Maybe (String, String, Bool)
isMapContainer (Class _ methods) = do
  guard $ all (`elem` methodNames) [ "insert", "get", "len", "keys" ]
  let kv = mapMaybe getKeyValue methods
      isMultiMap = length (L.nub $ snd <$> kv) > 1 
  (keyType, valueType) <- listToMaybe kv
  pure (keyType, valueType, isMultiMap)
  where
    methodNames = fun'name . method'fun <$> methods

    getKeyValue :: Method -> Maybe (String, String)
    getKeyValue method =
      case method of
        Method _ (Fun "insert" [Arg _ keyType, Arg _ valueType] _) ->
          Just (keyType, valueType)
        Method _ (Fun "get" [Arg _ keyType] valueType) ->
          Just (keyType, fromMaybe valueType $ L.stripSuffix " | void" valueType)
        _ ->
          Nothing

-- process standalone functions
funJs :: Fun -> String
funJs f = funJsBy (FunSpec "CSL" False "" (getPureness "" f)) f

funJsBy :: FunSpec -> Fun -> String
funJsBy (FunSpec parent isSkipFirst prefix pureness) (Fun name args _res) =
  unwords
  [ "export const"
  , prefix <> toName name
  , if L.null argNames
      then "="
      else "= " <> L.intercalate " => " argNames <> " =>"
  , withSemicolon $ mconcat $
    if pureness == Throwing
    then
      -- errorableToPurs(CSL.foo, arg1, arg2)
      [ "errorableToPurs("
      , parent
      , "."
      , name
      , if parent == "self" then ".bind(self)" else ""
      , ", "
      , L.intercalate ", " jsArgs
      , ")"
      ]
    else
      -- CSL.foo(arg1, arg2)
      [ parent
      , "."
      , name
      , if parent == "self" then ".bind(self)" else ""
      , "("
      , L.intercalate ", " jsArgs
      , ")"
      ]
  ]
  where
    -- if a function is mutating, we add another function wrapper that represents
    -- PureScript's `Effect` at runtime
    argNames = (if pureness == Mutating then (<> ["()"]) else id) argNamesIn
    argNamesIn = fmap (filter (/= '?')) $ arg'name <$> args
    jsArgs = (if isSkipFirst then tail else id) argNamesIn

withSemicolon :: String -> String
withSemicolon = flip mappend ";"

data HandleNulls = UseNullable | UseMaybe

commonInstances :: Class -> String
commonInstances (Class name methods) = unlines $
  [ "instance IsCsl " <> name <> " where\n  className _ = \"" <> name <> "\"" ] <>
  (if hasBytes
   then [ "instance IsBytes " <> name ]
   else []) <>
  (if hasJson
   then
      [ "instance IsJson " <> name
      , "instance EncodeAeson " <> name <> " where encodeAeson = cslToAeson"
      , "instance DecodeAeson " <> name <> " where decodeAeson = cslFromAeson"
      , "instance Show " <> name <> " where show = showViaJson"
      ]
   else
     if hasBytes
     then
       [ "instance EncodeAeson " <> name <> " where encodeAeson = cslToAesonViaBytes"
       , "instance DecodeAeson " <> name <> " where decodeAeson = cslFromAesonViaBytes"
       , "instance Show " <> name <> " where show = showViaBytes"
       ]
     else []
  )
  where
    hasBytes = hasInstanceMethod "to_bytes" && hasInstanceMethod "from_bytes"
    hasJson = hasInstanceMethod "to_json" && hasInstanceMethod "from_json"
    hasInstanceMethod str = Set.member str methodNameSet
    methodNameSet = Set.fromList $ fun'name . method'fun <$> methods

containerInstances :: Class -> Maybe String
containerInstances cls@(Class name _) =
  fmap unlines $
  notEmptyList $
  catMaybes
  [ isListContainer cls <&> \elemType ->
    "instance IsListContainer " <> unwords [ name, elemType ]
  , isMapContainer cls <&> \(keyType, valueType, isMultiMap) ->
      (if isMultiMap then "instance IsMultiMapContainer " else "instance IsMapContainer ")
        <> unwords [ name, keyType, valueType ]
  ]
  where
    notEmptyList :: [a] -> Maybe [a]
    notEmptyList [] = Nothing
    notEmptyList xs = Just xs

isCommon :: Fun -> Bool
isCommon (Fun "free" _ _) = True
isCommon (Fun "to_bytes" _ _) = True
isCommon (Fun "from_bytes" _ _) = True
isCommon (Fun "to_hex" _ _) = True
isCommon (Fun "from_hex" _ _) = True
isCommon (Fun "to_json" _ _) = True
isCommon (Fun "from_json" _ _) = True
isCommon (Fun "to_js_value" _ _) = True
isCommon (Fun "from_js_value" _ _) = True
-- sometimes these are with prefixes, sometimes not. they resist abstraction
-- isCommon (Fun "from_bech32" _ _) = True
-- isCommon (Fun "to_bech32" _ _) = True
isCommon (Fun "len" _ _) = True
isCommon (Fun "add" _ _) = True
isCommon (Fun "insert" _ _) = True
isCommon (Fun "get" _ _) = True
isCommon (Fun "keys" _ _) = True
isCommon (Fun _ _ _) = False

intro :: String -> String
intro str = unlines [ replicate 80 '-', "-- " <> str ]

classPurs :: Class -> String
classPurs cls@(Class name _ms) = mappend "\n" $
  L.intercalate "\n\n" $ fmap trim
    [ intro $ toTitle name
    , typePurs name
    , methodDefs
    , instances
    ]
  where
    filteredMethods = filterMethods cls

    methodDefs = unlines $ fmap toDef $ filteredMethods
      where
        toDef m = unwords ["foreign import", jsMethodName m, "::", psSig UseNullable m]

    jsMethodName Method{..} = methodName name (fun'name method'fun)

    psSig nullType m@Method{..} = trim $ unwords [ if L.null argTys then "" else (L.intercalate " -> " argTys <> " ->"), resTy]
      where
        addTypePrefix pref x
          | length (words x) > 1 = unwords [pref, "(" <> x <> ")"]
          | otherwise            = unwords [pref, x]

        argTys = handleNumArgs $ (if not (isObj m) then id else (toType name :)) $ fmap (handleVoid True . arg'type) $ fun'args $ method'fun
        resTy =
          let pureFun = isPure name method'fun
          in (case getPureness name method'fun of
                Pure -> id
                Mutating -> addTypePrefix "Effect"
                Throwing -> addTypePrefix "Nullable"
             ) $ handleVoid pureFun $ handleNumRes (fun'res $ method'fun)

        fromNullType = \case
          UseNullable -> "Nullable"
          UseMaybe -> "Maybe"

        handleVoid pureFun str
          | L.isSuffixOf "| void" str = (if pureFun then id else \a -> "(" <> a <> ")") $ fromNullType nullType <> " " <> (toType $ head $ splitOn "|" str)
          | otherwise               = toType str

        handleNumArgs =
          case Map.lookup (name, fun'name method'fun) intPos of
            Just subs -> substIntArgs subs . zip [0..]
            Nothing -> id

        handleNumRes =
          case Map.lookup (name, fun'name method'fun) intPos of
            Just subs -> substIntRes subs
            Nothing   -> id

    isObj Method{..} = case method'type of
      ObjectMethod -> True
      _ -> False

    instances = unlines $ catMaybes $
      [ Just $ commonInstances cls
      , containerInstances cls
      ]

-- | We assume that subst and args are sorted
substIntArgs :: [SigPos] -> [(Int, String)] -> [String]
substIntArgs ps args =
  case ps of
    [] -> fmap snd args
    ResPos : _ -> fmap snd args
    ArgPos n : restPos ->
      case args of
        [] -> []
        (m, arg) : restArgs | n == m -> substInt arg : substIntArgs restPos restArgs
        (_, arg) : restArgs -> arg : substIntArgs (ArgPos n : restPos) restArgs


substIntRes :: [SigPos] -> String -> String
substIntRes = \case
  [] -> id
  ResPos : _ -> substInt
  _ : rest -> substIntRes rest

substInt :: String -> String
substInt = replace "Number" "Int" . replace "number" "int"

filterMethods :: Class -> [Method]
filterMethods (Class name ms)
  -- CostModel is a special case: it looks like a mapping type, but isn't
  | name `elem` ["PublicKey", "PrivateKey", "CostModel", "VotingProcedures"] =
      filter (not . isIgnored . method'fun) ms -- these types need special handling
  | otherwise = filter (not . isCommon . method'fun) ms
  where
    -- we still need to remove `to_js_value`, because its return type is unknown
    isIgnored :: Fun -> Bool
    isIgnored  (Fun "to_js_value" _ _) = True
    isIgnored _ = False

classJs :: Class -> String
classJs cls@(Class name _ms) =
  unlines $ pre : (methodJs name <$> filterMethods cls)
  where
    pre = "// " <> name

methodJs :: String -> Method -> String
methodJs className m = toFun m
  where
    toFun (Method ty f) = case ty of
      StaticMethod ->
        funJsBy (FunSpec ("CSL." <> className) False pre (getPureness className f)) f
      ObjectMethod ->
        funJsBy (FunSpec "self" True pre (getPureness className f)) (f { fun'args = Arg "self" className : fun'args f })
    pre = toTypePrefix className <> "_"

methodName :: String -> String -> String
methodName className name = toTypePrefix className <> "_" <> toName name

toTypePrefix :: String -> String
toTypePrefix = lowerHead . subst . upperHead . toCamel

toType :: String -> String
toType = dropPrefix "ValuesTypeof" . subst . upperHead . toCamel

toName :: String -> String
toName = lowerHead . substFirst . subst . toCamel

subst :: String -> String
subst = replacesBy replace
  [ ("Uint8Array", "ByteArray")
  , ("Void", "Unit")
  , ("JSON", "Json")
  ]

substFirst :: String -> String
substFirst = replacesBy replaceFirst
  [
  ]

replaceFirst :: String -> String -> String -> String
replaceFirst from to str
  | L.isPrefixOf from str = to <> drop (length from) str
  | otherwise = str

replacesBy :: (String -> String -> String -> String) -> [(String, String)] -> String -> String
replacesBy repl = L.foldl' (\res a -> res . uncurry repl a) id

replace :: String -> String -> String -> String
replace from to = T.unpack . T.replace (T.pack from) (T.pack to) . T.pack

wrapText :: (Text -> Text) -> (String -> String)
wrapText f = T.unpack . f . T.pack

toTitle :: String -> String
toTitle = unwords . go . words . wrapText T.toTitle
  where
    go = \case
      [] -> []
      a:as -> a : fmap lowerHead as

toCamel :: String -> String
toCamel = wrapText T.toCamel

upperHead :: String -> String
upperHead = wrapText T.upperHead

lowerHead :: String -> String
lowerHead str
  | L.null post = fmap toLower str
  | otherwise =
    case pre of
        [] -> wrapText T.lowerHead post
        [a] -> toLower a : post
        _  -> map toLower (init pre) <> [last pre] <> post
  where
    (pre, post) = span isUpper str

data Pureness = Pure | Mutating | Throwing
  deriving (Eq, Show)

getPureness :: String -> Fun -> Pureness
getPureness className Fun{..}
  | isConvertor fun'name = Pure
  | take 4 fun'name `elem` [ "set_", "add_" ] = Mutating
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

convertorSet :: Set String
convertorSet = Set.fromList $ (\x -> fmap (<> x ) ["to_"]) =<<
  ["hex", "string", "bytes", "bech32", "json", "js_value"]

mutatingMethods :: (String, String) -> Bool
mutatingMethods a = Set.member a mutating

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

throwingSet :: Set (String, String)
throwingSet = mconcat $
  [ inClass "BigNum"
    [ "checked_mul"
    , "checked_add"
    , "checked_sub"
    ]
  , inClass "Value"
    [ "checked_add"
    , "checked_sub"
    ]
  , inClass "PublicKey"
    [ "from_bytes" ]
  , inClass "PrivateKey"
    [ "from_normal_bytes" ]
  , inClass "ByronAddress"
    [ "from_base58" ]
  , inClass "TransactionMetadatum"
    [ "as_map", "as_list", "as_int", "as_bytes", "as_text" ]
  ]
  where
    inClass name ms = Set.fromList $ fmap (name, ) ms

mutating :: Set (String, String)
mutating =
  mconcat $
    [ keys "Assets"
    , inClass "TransactionBuilder" ["new"]
    , inClass "TransactionWitnessSet" ["new"]
    , inClass "AuxiliaryData"
      [ "new", "set_native_scripts", "set_plutus_scripts", "set_metadata", "set_prefer_alonzo_format" ]
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
    ] ++ map (list . fst) listTypes
  where
    inClass name ms = Set.fromList $ fmap (name, ) ms
    list name = inClass name ["new", "get", "add", "len"]
    newSetGet name = inClass name ["new", "set", "get", "len"]
    keys name = inClass name ["new", "insert", "get", "keys", "len"]

-- | Position of the type in the signature
data SigPos = ResPos | ArgPos Int

-- | Which numbers should be treated as Int's.
-- Position is in the Purs signature (with extended object methods)
intPos :: Map (String, String) [SigPos]
intPos = mempty

-- | Is function pure and can throw (in this case we can catch it to Maybe on purs side)
-- if it's global function use empty name for class
isCommonThrowingMethod :: String -> Bool
isCommonThrowingMethod method = Set.member method froms
  where
    froms = Set.fromList
      [ "from_hex"
      , "from_bytes"
      , "from_normal_bytes"
      , "from_extended_bytes"
      , "from_bech32"
      , "from_json"
      , "from_str"
      ]

enumName :: CslEnum -> String
enumName e = enum'name e <> "Values"

enumPurs :: CslEnum -> String
enumPurs enum@(CslEnum nameForeign cases) =
  unlines
    [ intro nameForeign
    , enumForeign
    , ""
    , enumNative
    ]
  where
    name :: String
    name = enumName enum

    fixConstr :: String -> String
    fixConstr constr = nameForeign <> "_" <> constr

    enumForeign :: String
    enumForeign =
      unwords
        [ "foreign import data"
        , nameForeign
        , ":: Type"
        ]

    enumNative :: String
    enumNative =
      unlines $
        [ "data " <> name
        , "  = " <> L.intercalate "\n  | " (map fixConstr cases)
        , ""
        , "derive instance Generic " <> name <> " _"
        , "instance IsCslEnum " <> name <> " " <> nameForeign
        , "instance Show " <> name <> " where show = genericShow"
        ]
