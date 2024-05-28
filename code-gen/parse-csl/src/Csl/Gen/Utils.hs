module Csl.Gen.Utils (
  SigPos (..),
  classMethods,
  classTypes,
  enumName,
  filterMethods,
  intro,
  isCommon,
  isListContainer,
  isMapContainer,
  lowerHead,
  methodName,
  postProcTypes,
  replace,
  substInt,
  substIntArgs,
  substIntRes,
  toName,
  toTitle,
  toType,
  toTypePrefix,
  withSemicolon,
  wrapText,
) where

import Control.Monad (guard)
import Csl.Types
import Data.Char (isUpper, toLower)
import Data.List qualified as L (foldl', null)
import Data.List.Extra (dropPrefix, isPrefixOf)
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
import Data.Text (Text)
import Data.Text qualified as T (pack, replace, unpack)
import Data.Text.Manipulate qualified as T (lowerHead, toCamel, toTitle, upperHead)

toName :: String -> String
toName = lowerHead . substFirst . subst . toCamel

toTypePrefix :: String -> String
toTypePrefix = lowerHead . subst . upperHead . toCamel

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

withSemicolon :: String -> String
withSemicolon = flip mappend ";"

replaceFirst :: String -> String -> String -> String
replaceFirst from to str
  | from `isPrefixOf` str = to <> drop (length from) str
  | otherwise = str

substFirst :: String -> String
substFirst = replacesBy replaceFirst []

subst :: String -> String
subst =
  replacesBy
    replace
    [ ("Uint8Array", "ByteArray")
    , ("Void", "Unit")
    , ("JSON", "Json")
    ]

replacesBy :: (String -> String -> String -> String) -> [(String, String)] -> String -> String
replacesBy repl = L.foldl' (\res a -> res . uncurry repl a) id

replace :: String -> String -> String -> String
replace from to = T.unpack . T.replace (T.pack from) (T.pack to) . T.pack

wrapText :: (Text -> Text) -> (String -> String)
wrapText f = T.unpack . f . T.pack

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
        _ -> map toLower (init pre) <> [last pre] <> post
  where
    (pre, post) = span isUpper str

filterMethods :: Class -> [Method]
filterMethods (Class name ms)
  -- CostModel is a special case: it looks like a mapping type, but isn't
  | name `elem` ["PublicKey", "PrivateKey", "CostModel", "VotingProcedures"] =
      filter (not . isIgnored . method'fun) ms -- these types need special handling
  | otherwise = filter (not . isCommon . method'fun) ms
  where
    -- we still need to remove `to_js_value`, because its return type is unknown
    isIgnored :: Fun -> Bool
    isIgnored (Fun "to_js_value" _ _) = True
    isIgnored _ = False

toTitle :: String -> String
toTitle = unwords . go . words . wrapText T.toTitle
  where
    go = \case
      [] -> []
      a : as -> a : fmap lowerHead as

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
isMapContainer (Class _ methods) = do
  guard $ all (`elem` methodNames) ["insert", "get", "len", "keys"]
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
        (m, arg) : restArgs | n == m -> substInt arg : substIntArgs restPos restArgs
        (_, arg) : restArgs -> arg : substIntArgs (ArgPos n : restPos) restArgs

substIntRes :: [SigPos] -> String -> String
substIntRes = \case
  [] -> id
  ResPos : _ -> substInt
  _ : rest -> substIntRes rest

substInt :: String -> String
substInt = replace "Number" "Int" . replace "number" "int"

-- Remove standard types and transform case
postProcTypes :: [String] -> [String]
postProcTypes = filter (not . flip Set.member standardTypes) . fmap toType . L.sort . L.nub
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
