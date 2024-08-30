module Csl.Gen.Lib (
  SigPos (ResPos, ArgPos),
  classMethods,
  classTypes,
  enumName,
  filterMethods,
  intro,
  isCommon,
  isListContainer,
  isMapContainer,
  methodName,
  postProcTypes,
  subst,
  substInt,
  substIntArgs,
  substIntRes,
  toName,
  toType,
  toTypePrefix,
) where

import Control.Monad (guard)
import Csl.Gen.Utils (
  lowerHead,
  replace,
  replaceFirst,
  replacesBy,
  toCamel,
  upperHead,
 )
import Csl.Types
import Data.List.Extra (dropPrefix)
import Data.List.Extra qualified as L (
  nub,
  sort,
  stripSuffix,
 )
import Data.Maybe (
  fromMaybe,
  listToMaybe,
  mapMaybe,
 )
import Data.Set (Set)
import Data.Set qualified as Set

---- JavaScript/PureScript utilities

substFirst :: String -> String
substFirst = replacesBy replaceFirst []

toName :: String -> String
toName = lowerHead . substFirst . subst . toCamel

subst :: String -> String
subst =
  replacesBy
    replace
    [ ("Uint8Array", "ByteArray")
    , ("Void", "Unit")
    , ("JSON", "Json")
    ]

toType :: String -> String
toType = dropPrefix "ValuesTypeof" . subst . upperHead . toCamel

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
isCommon _ = False

filterMethods :: Class -> [Method]
filterMethods (Class name ms)
  -- CostModel and VotingProcedures are special cases: they are not normal maps
  -- and must expose their methods.
  | name `elem` ["PublicKey", "PrivateKey", "CostModel", "VotingProcedures"] =
      -- these types need special handling
      filter (not . isIgnored . method'fun) ms
  | otherwise = filter (not . isCommon . method'fun) ms
  where
    -- we still need to remove `to_js_value`, because its return type is
    -- unknown
    isIgnored :: Fun -> Bool
    isIgnored (Fun "to_js_value" _ _) = True
    isIgnored _ = False

-- Purescript utilities

intro :: String -> String
intro str = unlines [replicate 80 '-', "-- " <> str]

enumName :: CslEnum -> String
enumName e = enum'name e <> "Values"

isListContainer :: Class -> Maybe String
isListContainer (Class _ methods) = do
  guard $ all (`elem` methodNames) ["add", "len", "get"]
  listToMaybe $ mapMaybe getElement methods
  where
    methodNames = fun'name . method'fun <$> methods
    getElement :: Method -> Maybe String
    getElement (Method _ (Fun "add" [Arg _ elemType] _)) = Just elemType
    getElement _ = Nothing

isMapContainer :: Class -> Maybe (String, String, Bool)
isMapContainer (Class "Mint" _) = Just ("ScriptHash", "MintsAssets", False)
isMapContainer (Class name methods) = do
  guard $ all (`elem` methodNames) ["insert", "get", "len", "keys"]
  let kv = mapMaybe getKeyValue methods
      isMultiMap = name `elem` knownMultiMapContainers
  (keyType, valueType) <- listToMaybe kv
  pure (keyType, valueType, isMultiMap)
  where
    knownMultiMapContainers = ["PlutusMap"]

    methodNames = fun'name . method'fun <$> methods

    getKeyValue :: Method -> Maybe (String, String)
    getKeyValue method =
      case method of
        Method _ (Fun "get" [Arg _ keyType] valueType) ->
          Just
            ( keyType
            , fromMaybe valueType $
                L.stripSuffix " | void" valueType
            )
        Method _ (Fun "insert" [Arg _ keyType, Arg _ valueType] _) ->
          Just (keyType, valueType)
        _ ->
          Nothing

-- | Position of the type in the signature
data SigPos = ResPos | ArgPos Int

-- | We assume that subst and args are sorted
substIntArgs :: [SigPos] -> [(Int, String)] -> [String]
substIntArgs ps args =
  case ps of
    [] -> fmap snd args
    ResPos : _ -> fmap snd args
    ArgPos n : restPos ->
      case args of
        [] -> []
        (m, arg) : restArgs
          | n == m ->
              substInt arg : substIntArgs restPos restArgs
        (_, arg) : restArgs ->
          arg : substIntArgs (ArgPos n : restPos) restArgs

substIntRes :: [SigPos] -> String -> String
substIntRes = \case
  [] -> id
  ResPos : _ -> substInt
  _ : rest -> substIntRes rest

substInt :: String -> String
substInt = replace "Number" "Int" . replace "number" "int"

-- Remove standard types and transform case
postProcTypes :: [String] -> [String]
postProcTypes =
  filter (not . flip Set.member standardTypes)
    . fmap toType
    . L.sort
    . L.nub
  where
    standardTypes :: Set String
    standardTypes =
      Set.fromList
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
    fromClass Class {..} = [class'name]

classMethods :: Class -> [String]
classMethods cls@(Class name _ms) =
  map (mappend (toTypePrefix name <> "_") . toName . fun'name . method'fun) $
    filterMethods cls

methodName :: String -> String -> String
methodName className name_ = toTypePrefix className <> "_" <> toName name_

toTypePrefix :: String -> String
toTypePrefix = lowerHead . subst . upperHead . toCamel
