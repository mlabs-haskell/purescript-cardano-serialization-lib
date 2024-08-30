module Cardano.Serialization.Lib.Internal where

import Prelude

import Aeson (Aeson, decodeAeson, encodeAeson, jsonToAeson, stringifyAeson)
import Data.Argonaut (Json, JsonDecodeError(TypeMismatch), jsonParser, stringify)
import Data.Bifunctor (lmap)
import Data.ByteArray (ByteArray)
import Data.Either (Either, note)
import Data.Enum.Generic (class GenericBoundedEnum, genericFromEnum, genericToEnum)
import Data.Generic.Rep (class Generic)
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(Nothing, Just), fromJust)
import Data.Profunctor.Strong ((***))
import Data.Tuple (Tuple(Tuple))
import Data.Tuple.Nested (type (/\), (/\))
import Partial.Unsafe (unsafePartial)
import Type.Proxy (Proxy(Proxy))
import Unsafe.Coerce (unsafeCoerce)

-- all types

class IsCsl (a :: Type) where
  className :: Proxy a -> String

-- byte-representable types

class IsCsl a <= IsBytes (a :: Type)

toBytes :: forall a. IsCsl a => IsBytes a => a -> ByteArray
toBytes = _toBytes

fromBytes :: forall a. IsCsl a => IsBytes a => ByteArray -> Maybe a
fromBytes = _fromBytes (className (Proxy :: Proxy a)) Nothing Just

foreign import _toBytes :: forall a. a -> ByteArray

foreign import _fromBytes
  :: forall b
   . String
  -> (forall a. Maybe a)
  -> (forall a. a -> Maybe a)
  -> ByteArray
  -> Maybe b

-- json

class IsCsl a <= IsJson (a :: Type)

-- enums

class IsCslEnum (e :: Type) (f :: Type) | e -> f, f -> e

toCslEnum :: forall e f rep. IsCslEnum e f => Generic e rep => GenericBoundedEnum rep => e -> f
toCslEnum = unsafeCoerce <<< genericFromEnum

fromCslEnum :: forall e f rep. IsCslEnum e f => Generic e rep => GenericBoundedEnum rep => f -> e
fromCslEnum = unsafePartial fromJust <<< genericToEnum <<< unsafeCoerce

-- containers

class IsListContainer (c :: Type) (e :: Type) | c -> e

packListContainer :: forall c e. IsCsl c => IsListContainer c e => Array e -> c
packListContainer = _packListContainer false (className (Proxy :: Proxy c))

packListContainerWithClone :: forall c e. IsCsl c => IsListContainer c e => Array e -> c
packListContainerWithClone = _packListContainer true (className (Proxy :: Proxy c))

unpackListContainer :: forall c e. IsListContainer c e => c -> Array e
unpackListContainer = _unpackListContainer

foreign import _packListContainer :: forall c e. Boolean -> String -> Array e -> c
foreign import _unpackListContainer :: forall c e. c -> Array e

class IsMultiMapContainer (c :: Type) (k :: Type) (vs :: Type) | c -> k, c -> vs

packMultiMapContainer
  :: forall c k vs
   . IsMultiMapContainer c k vs
  => IsCsl c
  => Array (k /\ vs)
  -> c
packMultiMapContainer = map toKeyValues >>> _packMapContainer false (className (Proxy :: Proxy c))
  where
  toKeyValues (Tuple key value) = { key, value }

packMultiMapContainerWithClone
  :: forall c k vs
   . IsMultiMapContainer c k vs
  => IsCsl c
  => Array (k /\ vs)
  -> c
packMultiMapContainerWithClone = map toKeyValues >>> _packMapContainer true (className (Proxy :: Proxy c))
  where
  toKeyValues (Tuple key value) = { key, value }

unpackMultiMapContainer
  :: forall c k vs
   . IsMultiMapContainer c k vs
  => c
  -> Array (k /\ vs)
unpackMultiMapContainer = _unpackMultiMapContainer >>> map fromKV
  where
  fromKV { key, values } = key /\ values

unpackMultiMapContainerToMapWith
  :: forall c k vs k1 v1
   . IsMultiMapContainer c k vs
  => Ord k1
  => (k -> k1)
  -> (vs -> Array v1)
  -> c
  -> Map k1 v1
unpackMultiMapContainerToMapWith mapKey mapValues container =
  unpackMultiMapContainer container
    # map (mapKey *** mapValues)
    # flip bind (\(k /\ vs) -> vs >>= pure <<< Tuple k)
    # Map.fromFoldable

class IsMapContainer (c :: Type) (k :: Type) (v :: Type) | c -> k, c -> v

packMapContainer
  :: forall c k v
   . IsMapContainer c k v
  => IsCsl c
  => Array (k /\ v)
  -> c
packMapContainer = map toKeyValues >>> _packMapContainer false (className (Proxy :: Proxy c))
  where
  toKeyValues (Tuple key value) = { key, value }

packMapContainerWithClone
  :: forall c k v
   . IsMapContainer c k v
  => IsCsl c
  => Array (k /\ v)
  -> c
packMapContainerWithClone = map toKeyValues >>> _packMapContainer true (className (Proxy :: Proxy c))
  where
  toKeyValues (Tuple key value) = { key, value }

packMapContainerFromMap
  :: forall c k v
   . IsMapContainer c k v
  => IsCsl c
  => IsCsl k
  => IsCsl v
  => Map k v
  -> c
packMapContainerFromMap = packMapContainer <<< Map.toUnfoldable

unpackMapContainer
  :: forall c k v
   . IsMapContainer c k v
  => c
  -> Array (k /\ v)
unpackMapContainer = _unpackMapContainer >>> map fromKV
  where
  fromKV { key, value } = key /\ value

unpackMapContainerToMapWith
  :: forall c k v k1 v1
   . IsMapContainer c k v
  => Ord k1
  => (k -> k1)
  -> (v -> v1)
  -> c
  -> Map k1 v1
unpackMapContainerToMapWith mapKey mapValue container =
  unpackMapContainer container
    # map (mapKey *** mapValue) >>> Map.fromFoldable

foreign import _packMapContainer
  :: forall c k v
   . Boolean
  -> String
  -> Array { key :: k, value :: v }
  -> c

foreign import _unpackMapContainer
  :: forall c k v
   . c
  -> Array { key :: k, value :: v }

foreign import _unpackMultiMapContainer
  :: forall c k vs
   . c
  -> Array { key :: k, values :: vs }

-- Aeson

cslFromAeson
  :: forall a
   . IsJson a
  => Aeson
  -> Either JsonDecodeError a
cslFromAeson aeson =
  (lmap (const $ TypeMismatch "JSON") $ jsonParser $ stringifyAeson aeson)
    >>= cslFromJson >>> note (TypeMismatch $ className (Proxy :: Proxy a))

cslToAeson
  :: forall a
   . IsJson a
  => a
  -> Aeson
cslToAeson = _cslToJson >>> jsonToAeson

cslToAesonViaBytes
  :: forall a
   . IsBytes a
  => a
  -> Aeson
cslToAesonViaBytes = toBytes >>> encodeAeson

cslFromAesonViaBytes
  :: forall a
   . IsBytes a
  => Aeson
  -> Either JsonDecodeError a
cslFromAesonViaBytes aeson = do
  bytes <- decodeAeson aeson
  note (TypeMismatch $ className (Proxy :: Proxy a)) $ fromBytes bytes

-- Show

showViaBytes
  :: forall a
   . IsBytes a
  => a
  -> String
showViaBytes a = "(unsafePartial $ fromJust $ fromBytes " <> show (toBytes a) <> ")"

showViaJson
  :: forall a
   . IsJson a
  => a
  -> String
showViaJson a = "(unsafePartial $ fromJust $ cslFromJson $ jsonParser " <> show (stringify (_cslToJson a)) <> ")"

--- Json

cslFromJson :: forall a. IsCsl a => IsJson a => Json -> Maybe a
cslFromJson = _cslFromJson (className (Proxy :: Proxy a)) Nothing Just

foreign import _cslFromJson
  :: forall b
   . String
  -> (forall a. Maybe a)
  -> (forall a. a -> Maybe a)
  -> Json
  -> Maybe b

foreign import _cslToJson :: forall a. a -> Json
