module Csl.Parse where

import           Control.Monad   (guard)
import           Csl.Types
import           Data.List       as L
import           Data.List.Extra (breakOn, trim)
import           Data.List.Split (splitOn)
import           Data.Maybe      (mapMaybe)

toFunParts :: String -> [String]
toFunParts = splitOn "\n\n"

funs :: String -> [Fun]
funs = mapMaybe parseFun . toFunParts

parseFun :: String -> Maybe Fun
parseFun str =
  case splitOn funPrefix str of
    [_, content] -> funBody content
    _            -> Nothing

funBody :: String -> Maybe Fun
funBody content = do
  (name, rest1) <- split2 "(" content
  (args, rest2) <- split2 "):" rest1
  (res, _) <- split2 ";" rest2
  pure $ Fun (trim name) (parseArgs args) (trim res)

split2 :: String -> String -> Maybe (String, String)
split2 delim str = case splitOn delim str of
  [a, b] -> Just (a, b)
  _      -> Nothing

parseArgs :: String -> [Arg]
parseArgs str = mapMaybe parseArg $ splitOn "," str

parseArg :: String -> Maybe Arg
parseArg str =
  case splitOn ":" str of
    [a, b] -> Just $ Arg (trim a) (trim b)
    _      -> Nothing

toClassParts = tail . splitOn classPrefix

parseClass :: String -> Class
parseClass str = Class (trim name) ms
  where
    name : rest1 = splitOn " {" (removeComments str)
    body : _ = splitOn "}" (mconcat rest1)
    ms = mapMaybe parseMethods $ fmap (<> ";") $ splitOn ";" body

parseMethods :: String -> Maybe Method
parseMethods str = toMethod <$> funBody str
  where
    toMethod x
      | L.isPrefixOf "static " (fun'name x) = Method StaticMethod (rmStaticPrefix x)
      | otherwise                           = Method ObjectMethod x

    rmStaticPrefix x = x { fun'name = drop 7 $ fun'name x }

toEnumParts :: String -> [String]
toEnumParts = tail . splitOn enumPrefix

enums :: String -> [CslEnum]
enums = mapMaybe parseEnum . toEnumParts

parseEnum :: String -> Maybe CslEnum
parseEnum str = do 
  (name, rest1) <- split2 ": {|" str
  (cases, _) <- split2 "|}" rest1 
  pure $ CslEnum (trim name) (parseEnumCases cases)  

parseEnumCases :: String -> [String]
parseEnumCases = map (fst . breakOn ":") . tail . splitOn "+"

----------------------------------------------------------------------------
-- const

classPrefix = "declare export class "
funPrefix = "declare export function "
enumPrefix = "declare export var "

-- Taken from Emurgo/cardano-serialization-lib (v12.0.0-alpha.31):
-- https://github.com/Emurgo/cardano-serialization-lib/blob/3eb710750347b88e92a95deca55080c389eba107/rust/pkg/cardano_serialization_lib.js.flow
file = "data/cardano_serialization_lib.js.flow"

----------------------------------------------------------------------------
-- utils

removeComments :: String -> String
removeComments str = mconcat $
  case splitOn "/*" str of
    []     -> []
    a:[]   -> [a]
    a:rest -> a : fmap (mconcat . tail . splitOn "*/") rest
