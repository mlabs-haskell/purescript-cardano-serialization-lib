module Csl.Types where

data Arg = Arg
  { arg'name :: String
  , arg'type :: String
  }
  deriving (Show)

data Fun = Fun
  { fun'name :: String
  , fun'args :: [Arg]
  , fun'res  :: String
  }
  deriving (Show)

data Class = Class
  { class'name :: String
  , class'methods :: [Method]
  }
  deriving (Show)

data MethodType = StaticMethod | ObjectMethod
  deriving (Show)

data Method = Method
  { method'type :: MethodType
  , method'fun :: Fun
  }
  deriving (Show)

data CslEnum = CslEnum
  { enum'name :: String
  , enum'cases :: [String]
  }
  deriving (Show)
