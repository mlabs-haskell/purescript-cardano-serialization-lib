import Prelude

import Cardano.Serialization.Lib.Internal
  ( class IsBytes
  , class IsCsl
  , class IsCslEnum
  , class IsJson
  , class IsListContainer
  , class IsMapContainer
  , class IsMultiMapContainer
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
  , class IsCslEnum
  , class IsJson
  , toBytes
  , fromBytes
  , packListContainer
  , packMapContainer
  , packMapContainerFromMap
  , packMultiMapContainer
  , unpackMapContainerToMapWith
  , unpackMapContainer
  , unpackMultiMapContainer
  , unpackMultiMapContainerToMapWith
  , unpackListContainer
  , cslFromAeson
  , cslToAeson
  , cslFromAesonViaBytes
  , cslToAesonViaBytes
  , toCslEnum
  , fromCslEnum
  ) as X
import Aeson (class DecodeAeson, class EncodeAeson)
import Data.ByteArray (ByteArray)
import Data.Generic.Rep (class Generic)
import Data.Maybe (Maybe)
import Data.Nullable (Nullable)
import Data.Show.Generic (genericShow)
import Effect (Effect)

class IsStr a where
  fromStr :: String -> Maybe a
  toStr :: a -> String
