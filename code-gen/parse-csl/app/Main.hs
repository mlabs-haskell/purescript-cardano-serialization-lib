module Main (main) where

import           Csl
import           System.Directory   (createDirectoryIfMissing)
import           System.Environment (getArgs)
import           System.FilePath    (takeDirectory)

main :: IO ()
main = do
  exportPath <- (<> "/") . head <$> getArgs
  jsLibHeader <- readFile "./fixtures/Lib.js"
  importsCode <- readFile "./fixtures/imports.purs"
  pursInternalLib <- readFile "./fixtures/Internal.purs"
  jsInternalLib <- readFile "./fixtures/Internal.js"
  funs <- getFuns
  classes <- getClasses
  print funs
  -- print classes
  let
    nonCommonFuns = filter (not . isCommon) funs
    funsJsCode = unlines $ funJs <$> nonCommonFuns
    funsPursCode = unlines $ funPurs <$> nonCommonFuns
    classesPursCode = unlines $ classPurs <$> classes
    classesJsCode = unlines $ classJs <$> classes
    exportsPursCode = exportListPurs nonCommonFuns classes
  createDirectoryIfMissing True $ takeDirectory $ exportPath <> "/"
  createDirectoryIfMissing True $ takeDirectory $ exportPath <> "/Lib/"
  writeFile (exportPath <> "Lib.purs") $ unlines
    [ pursLibHeader ++ exportsPursCode ++ "\n  ) where"
    , importsCode
    , ""
    , "-- functions"
    , funsPursCode
    , ""
    , "-- classes"
    , ""
    , classesPursCode
    ]
  writeFile (exportPath <> "Lib.js") $ unlines
    [ jsLibHeader
    , classesJsCode
    , funsJsCode
    ]
  writeFile (exportPath <> "Lib/Internal.purs") pursInternalLib
  writeFile (exportPath <> "Lib/Internal.js") jsInternalLib

pursLibHeader = "module Cardano.Serialization.Lib\n  ( "
