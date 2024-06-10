module Test.Main where

import Prelude

import Aeson (encodeAeson)
import Cardano.Serialization.Lib
  ( PlutusList
  , bigInt_fromStr
  , bigNum_fromStr
  , constrPlutusData_new
  , cslToAesonViaBytes
  , hashPlutusData
  , packListContainer
  , plutusData_newConstrPlutusData
  , plutusData_newInteger
  , plutusList_new
  , transactionWitnessSet_new
  , transactionWitnessSet_setPlutusData
  )
import Control.Monad.Error.Class (class MonadThrow)
import Data.Maybe (fromJust)
import Data.Nullable (Nullable, toMaybe)
import Effect (Effect)
import Effect.Aff (Error, launchAff_)
import Effect.Class (class MonadEffect, liftEffect)
import Partial.Unsafe (unsafePartial)
import Test.Spec (Spec, describe, it)
import Test.Spec.Assertions (shouldEqual)
import Test.Spec.Reporter.Console (consoleReporter)
import Test.Spec.Runner (runSpec)

-- Note: most of the tests should be place at `mlabs-haskell/purescript-cardano-types`,
-- where proper roundtrip tests can be performed.

main :: Effect Unit
main = launchAff_ $ runSpec [ consoleReporter ] spec

nonNull :: forall a. Nullable a -> a
nonNull x = unsafePartial $ fromJust $ toMaybe x

-- Tests adapted from https://github.com/Emurgo/cardano-serialization-lib/blob/evgenii/conway_certs/rust/src/tests/plutus.rs
legacyOutputRoundtrip
  :: forall a
   . Bind a
  => MonadEffect a
  => MonadThrow Error a
  => a Unit
legacyOutputRoundtrip = do
  plutusList <- liftEffect plutusList_new
  let
    constr0 = plutusData_newConstrPlutusData $
      constrPlutusData_new (nonNull $ bigNum_fromStr "0") plutusList
    constr0Hash = encodeAeson $ hashPlutusData constr0
  (show constr0Hash) `shouldEqual`
    "\"923918e403bf43c34b4ef6b48eb2ee04babed17320d8d1b9ff9ad086e86f44ec\""

plutusListSerializationCliCompatibility
  :: forall a
   . Bind a
  => MonadEffect a
  => MonadThrow Error a
  => a Unit
plutusListSerializationCliCompatibility = do
  let
    plutusData = plutusData_newInteger (nonNull $ bigInt_fromStr "1")

    plutusList :: PlutusList
    plutusList = packListContainer [ plutusData ]

  (show $ cslToAesonViaBytes plutusList) `shouldEqual` "\"9f01ff\""

  witnessSet <- liftEffect transactionWitnessSet_new
  liftEffect $ transactionWitnessSet_setPlutusData witnessSet plutusList

  (show $ cslToAesonViaBytes witnessSet) `shouldEqual` "\"a1049f01ff\""

spec :: Spec Unit
spec = do
  describe "Plutus" do
    it "Legacy output roundtrip" legacyOutputRoundtrip
    it "Plutus List Serialization CLI Compatibility"
      plutusListSerializationCliCompatibility

