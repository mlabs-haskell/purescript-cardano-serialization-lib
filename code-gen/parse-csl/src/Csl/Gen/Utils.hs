module Csl.Gen.Utils (
  lowerHead,
  replace,
  replaceFirst,
  replacesBy,
  toCamel,
  toTitle,
  upperHead,
  withSemicolon,
  wrapText,
) where

import Data.Char (isUpper, toLower)
import Data.List qualified as L (foldl', null)
import Data.List.Extra (isPrefixOf)
import Data.Text (Text)
import Data.Text qualified as T (pack, replace, unpack)
import Data.Text.Manipulate qualified as T (
  lowerHead,
  toCamel,
  toTitle,
  upperHead,
 )

withSemicolon :: String -> String
withSemicolon = flip mappend ";"

replaceFirst :: String -> String -> String -> String
replaceFirst from to str
  | from `isPrefixOf` str = to <> drop (length from) str
  | otherwise = str

replacesBy ::
  (String -> String -> String -> String) ->
  [(String, String)] ->
  String ->
  String
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

toTitle :: String -> String
toTitle = unwords . go . words . wrapText T.toTitle
  where
    go = \case
      [] -> []
      a : as -> a : fmap lowerHead as
