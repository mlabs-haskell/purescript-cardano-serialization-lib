import Prelude

import Cardano.Serialization.Lib.Internal
  ( class IsBytes
  , class IsCsl
  , class IsJson
  , class IsListContainer
  , class IsMapContainer
  , cslFromAeson
  , cslFromAesonViaBytes
  , cslToAeson
  , cslToAesonViaBytes
  , showViaBytes
  , showViaJson
  )
import Cardano.Serialization.Lib.Internal
  ( class IsBytes
  , class IsCsl
  , class IsJson
  , toBytes
  , fromBytes
  , packListContainer
  , packMapContainer
  , packMapContainerFromMap
  , unpackMapContainerToMapWith
  , unpackMapContainer
  , unpackListContainer
  , cslFromAeson
  , cslToAeson
  , cslFromAesonViaBytes
  , cslToAesonViaBytes
  ) as X
import Effect (Effect)
import Data.Nullable (Nullable)
import Aeson (class DecodeAeson, class EncodeAeson)
import Data.ByteArray (ByteArray)
import Data.Maybe (Maybe)

class IsStr a where
  fromStr :: String -> Maybe a
  toStr :: a -> String
