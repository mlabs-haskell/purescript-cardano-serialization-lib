module Csl (
  module Csl,
  module X,
) where

import Csl.Gen as X
import Csl.Parse as X
import Csl.Types as X

-------------------------------------------------------------------------------
-- read parts

getFuns :: IO [Fun]
getFuns =
  filter (flip elem neededFunctions . fun'name)
    . funs
    <$> readFile file

getClasses :: IO [Class]
getClasses =
  filter (not . flip elem unneededClasses . class'name)
    . fmap parseClass
    . toClassParts
    <$> readFile file

getEnums :: IO [CslEnum]
getEnums = enums <$> readFile file

unneededClasses :: [String]
unneededClasses =
  [ -- builder classes, not used by `ps-cardano-types`
    "CertificatesBuilder"
  , "TransactionBuilder"
  , "TransactionBuilderConfigBuilder"
  , "TransactionBuilderConfig"
  , "TransactionOutputAmountBuilder"
  , "TransactionOutputBuilder"
  , "TxBuilderConstants"
  , "TxInputsBuilder"
  , "MintBuilder"
  , "VotingBuilder"
  , "VotingProposalBuilder"
  , "WithdrawalsBuilder"
  , -- block data, not needed for `ps-cardano-types`
    "Block"
  , "Header"
  , "HeaderBody"
  , "TransactionBodies"
  , "AuxiliaryDataSet"
  , "TransactionWitnessSets"
  , -- Types that are not parts of a Transaction and are not needed
    "Strings"
  , "PublicKeys"
  , "FixedTransaction"
  ]

neededFunctions :: [String]
neededFunctions =
  [ "hash_auxiliary_data"
  , "hash_transaction"
  , "hash_plutus_data"
  , "min_ada_for_output"
  , "hash_script_data"
  , "min_script_fee"
  , "min_fee"
  , "make_vkey_witness"
  ]

-------------------------------------------------------------------------------
-- utils

genExport :: FilePath -> IO [a] -> (a -> String) -> IO ()
genExport name extract parse =
  exportFile name . unlines . fmap parse =<< extract

exportFile :: FilePath -> String -> IO ()
exportFile name = writeFile ("output/" <> name)
