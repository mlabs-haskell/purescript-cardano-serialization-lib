module Csl.Gen.PureScript (
  classPurs,
  enumPurs,
  exportListPurs,
  funPurs,
) where

import Csl.Gen.Lib (SigPos, classMethods, classTypes, enumName, filterMethods, intro, isListContainer, isMapContainer, methodName, substIntArgs, substIntRes, toName, toType)
import Csl.Gen.Types.FunPurity (FunPurity (Mutating, Pure, Throwing), getPureness, isPure)
import Csl.Gen.Utils (toTitle)
import Csl.Types
import Data.Functor ((<&>))
import Data.List.Extra (trim)
import Data.List.Extra qualified as L (
  intercalate,
  isSuffixOf,
  null,
 )
import Data.List.Split (splitOn)
import Data.Map (Map)
import Data.Map qualified as Map
import Data.Maybe (
  catMaybes,
 )
import Data.Set qualified as Set

exportListPurs :: [Fun] -> [Class] -> [CslEnum] -> String
exportListPurs funs cls enums =
  L.intercalate "\n  , " $
    extraExport
      ++ (classMethods =<< cls)
      ++ (toName . fun'name <$> funs)
      ++ (fromType =<< classTypes cls)
      ++ (enum'name <$> enums)
      ++ ((\x -> enumName x <> "(..)") <$> enums)
  where
    fromType ty = [ty]

    extraExport :: [String]
    extraExport =
      [ "module X"
      ]

typePurs :: String -> String
typePurs ty =
  unlines
    [ typeDefPurs ty
    ]

typeDefPurs :: String -> String
typeDefPurs ty
  | isJsonType ty = unwords ["type", ty, "= Json"]
  | otherwise = unwords ["foreign import data", ty, ":: Type"]
  where
    isJsonType :: String -> Bool
    isJsonType = L.isSuffixOf "Json"

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
    preComment :: String -> String
    preComment str = "-- | " <> str

    codeComment :: String -> String
    codeComment str = "-- > " <> str

    funName = toName name
    argTypeNames = toType . arg'type <$> args
    preFunComment = funCommentBy preComment

    funCommentBy title f =
      L.intercalate
        "\n"
        [ title (funTitleComment f)
        , codeComment (funCodeComment f)
        ]

    funTitleComment Fun {..} = toTitle fun'name
    funCodeComment Fun {..} = unwords [toName fun'name, unwords argNames]
      where
        argNames = toName . arg'name <$> fun'args

data HandleNulls = UseNullable | UseMaybe

classPurs :: Class -> String
classPurs cls@(Class name _ms) =
  mappend "\n" $
    L.intercalate "\n\n" $
      fmap
        trim
        [ intro $ toTitle name
        , typePurs name
        , methodDefs
        , instances
        ]
  where
    filteredMethods = filterMethods cls

    methodDefs = unlines $ toDef <$> filteredMethods
      where
        toDef m = unwords ["foreign import", jsMethodName m, "::", psSig UseNullable m]

    jsMethodName Method {..} = methodName name (fun'name method'fun)

    psSig nullType m@Method {..} = trim $ unwords [if L.null argTys then "" else L.intercalate " -> " argTys <> " ->", resTy]
      where
        addTypePrefix pref x
          | length (words x) > 1 = unwords [pref, "(" <> x <> ")"]
          | otherwise = unwords [pref, x]

        argTys = handleNumArgs $ (if not (isObj m) then id else (toType name :)) $ handleVoid True . arg'type <$> fun'args method'fun
        resTy =
          let pureFun = isPure name method'fun
           in ( case getPureness name method'fun of
                  Pure -> id
                  Mutating -> addTypePrefix "Effect"
                  Throwing -> addTypePrefix "Nullable"
              )
                $ handleVoid pureFun
                $ handleNumRes (fun'res method'fun)

        fromNullType = \case
          UseNullable -> "Nullable"
          UseMaybe -> "Maybe"

        handleVoid pureFun str
          | L.isSuffixOf "| void" str = (if pureFun then id else \a -> "(" <> a <> ")") $ fromNullType nullType <> " " <> toType (head $ splitOn "|" str)
          | otherwise = toType str

        handleNumArgs =
          case Map.lookup (name, fun'name method'fun) intPos of
            Just subs -> substIntArgs subs . zip [0 ..]
            Nothing -> id

        handleNumRes =
          maybe id substIntRes (Map.lookup (name, fun'name method'fun) intPos)

    isObj Method {..} = case method'type of
      ObjectMethod -> True
      _ -> False

    instances =
      unlines $
        catMaybes
          [ Just $ commonInstances cls
          , containerInstances cls
          ]

commonInstances :: Class -> String
commonInstances (Class name methods) =
  unlines $
    ["instance IsCsl " <> name <> " where\n  className _ = \"" <> name <> "\""]
      <> (["instance IsBytes " <> name | hasBytes])
      <> ( if hasJson
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
            "instance IsListContainer " <> unwords [name, elemType]
        , isMapContainer cls <&> \(keyType, valueType, isMultiMap) ->
            (if isMultiMap then "instance IsMultiMapContainer " else "instance IsMapContainer ")
              <> unwords [name, keyType, valueType]
        ]
  where
    notEmptyList :: [a] -> Maybe [a]
    notEmptyList [] = Nothing
    notEmptyList xs = Just xs

{- | Which numbers should be treated as Int's.
Position is in the Purs signature (with extended object methods)
-}
intPos :: Map (String, String) [SigPos]
intPos = mempty

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
      unlines
        [ "data " <> name
        , "  = " <> L.intercalate "\n  | " (map fixConstr cases)
        , ""
        , "derive instance Generic " <> name <> " _"
        , "instance IsCslEnum " <> name <> " " <> nameForeign
        , "instance Show " <> name <> " where show = genericShow"
        ]
