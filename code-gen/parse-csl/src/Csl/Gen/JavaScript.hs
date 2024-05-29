{-# OPTIONS_GHC -Wno-unused-top-binds #-}

module Csl.Gen.JavaScript (funJs, classJs) where

import Csl.Gen.Lib (filterMethods, toName, toTypePrefix)
import Csl.Gen.Types.FunPurity (FunPurity (Mutating, Throwing), getPureness)
import Csl.Gen.Utils (withSemicolon)
import Csl.Types
import Data.List.Extra qualified as L (intercalate, null)

data FunSpec = FunSpec
  { funSpec'parent :: String
  , funSpec'skipFirst :: Bool
  , funSpec'prefix :: String
  , funSpec'pureness :: FunPurity
  }

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
    , withSemicolon $
        mconcat $
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

classJs :: Class -> String
classJs cls@(Class name _ms) =
  unlines $ pre : (methodJs name <$> filterMethods cls)
  where
    pre = "// " <> name

methodJs :: String -> Method -> String
methodJs className = toFun
  where
    toFun (Method ty f) = case ty of
      StaticMethod ->
        funJsBy (FunSpec ("CSL." <> className) False pre (getPureness className f)) f
      ObjectMethod ->
        funJsBy (FunSpec "self" True pre (getPureness className f)) (f {fun'args = Arg "self" className : fun'args f})

    pre = toTypePrefix className <> "_"
