module Csl.Types (
  Arg (Arg, arg'name, arg'type),
  Fun (Fun, fun'name, fun'args, fun'res),
  Class (Class, class'name, class'methods),
  MethodType (StaticMethod, ObjectMethod),
  Method (Method, method'type, method'fun),
  CslEnum (CslEnum, enum'name, enum'cases),
) where

data Arg = Arg
  { arg'name :: String
  , arg'type :: String
  }
  deriving stock (Show)

data Fun = Fun
  { fun'name :: String
  , fun'args :: [Arg]
  , fun'res :: String
  }
  deriving stock (Show)

data Class = Class
  { class'name :: String
  , class'methods :: [Method]
  }
  deriving stock (Show)

data MethodType = StaticMethod | ObjectMethod
  deriving stock (Show)

data Method = Method
  { method'type :: MethodType
  , method'fun :: Fun
  }
  deriving stock (Show)

data CslEnum = CslEnum
  { enum'name :: String
  , enum'cases :: [String]
  }
  deriving stock (Show)
