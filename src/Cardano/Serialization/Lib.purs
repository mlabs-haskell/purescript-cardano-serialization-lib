module Cardano.Serialization.Lib
  ( module X
  , address_kind
  , address_paymentCred
  , address_isMalformed
  , address_toBech32
  , address_fromBech32
  , address_networkId
  , anchor_url
  , anchor_anchorDataHash
  , anchor_new
  , anchorDataHash_toBech32
  , anchorDataHash_fromBech32
  , assetName_new
  , assetName_name
  , assetNames_new
  , assets_new
  , auxiliaryData_new
  , auxiliaryData_metadata
  , auxiliaryData_setMetadata
  , auxiliaryData_nativeScripts
  , auxiliaryData_setNativeScripts
  , auxiliaryData_plutusScripts
  , auxiliaryData_setPlutusScripts
  , auxiliaryData_preferAlonzoFormat
  , auxiliaryData_setPreferAlonzoFormat
  , auxiliaryDataHash_toBech32
  , auxiliaryDataHash_fromBech32
  , baseAddress_new
  , baseAddress_paymentCred
  , baseAddress_stakeCred
  , baseAddress_toAddress
  , baseAddress_fromAddress
  , bigInt_isZero
  , bigInt_asU64
  , bigInt_asInt
  , bigInt_fromStr
  , bigInt_toStr
  , bigInt_mul
  , bigInt_one
  , bigInt_increment
  , bigInt_divCeil
  , bigNum_fromStr
  , bigNum_toStr
  , bigNum_zero
  , bigNum_one
  , bigNum_isZero
  , bigNum_divFloor
  , bigNum_checkedMul
  , bigNum_checkedAdd
  , bigNum_checkedSub
  , bigNum_clampedSub
  , bigNum_compare
  , bigNum_lessThan
  , bigNum_maxValue
  , bigNum_max
  , bip32PrivateKey_derive
  , bip32PrivateKey_from128Xprv
  , bip32PrivateKey_to128Xprv
  , bip32PrivateKey_generateEd25519Bip32
  , bip32PrivateKey_toRawKey
  , bip32PrivateKey_toPublic
  , bip32PrivateKey_asBytes
  , bip32PrivateKey_fromBech32
  , bip32PrivateKey_toBech32
  , bip32PrivateKey_fromBip39Entropy
  , bip32PrivateKey_chaincode
  , bip32PublicKey_chaincode
  , bip32PublicKey_toBech32
  , bip32PublicKey_fromBech32
  , bip32PublicKey_asBytes
  , bip32PublicKey_toRawKey
  , bip32PublicKey_derive
  , blockHash_toBech32
  , blockHash_fromBech32
  , bootstrapWitness_vkey
  , bootstrapWitness_signature
  , bootstrapWitness_chainCode
  , bootstrapWitness_attributes
  , bootstrapWitness_new
  , bootstrapWitnesses_new
  , byronAddress_toBase58
  , byronAddress_byronProtocolMagic
  , byronAddress_attributes
  , byronAddress_networkId
  , byronAddress_fromBase58
  , byronAddress_icarusFromKey
  , byronAddress_isValid
  , byronAddress_toAddress
  , byronAddress_fromAddress
  , certificate_newStakeRegistration
  , certificate_newStakeDeregistration
  , certificate_newStakeDelegation
  , certificate_newPoolRegistration
  , certificate_newPoolRetirement
  , certificate_newGenesisKeyDelegation
  , certificate_newMoveInstantaneousRewardsCert
  , certificate_newCommitteeHotAuth
  , certificate_newCommitteeColdResign
  , certificate_newDrepDeregistration
  , certificate_newDrepRegistration
  , certificate_newDrepUpdate
  , certificate_newStakeAndVoteDelegation
  , certificate_newStakeRegistrationAndDelegation
  , certificate_newStakeVoteRegistrationAndDelegation
  , certificate_newVoteDelegation
  , certificate_newVoteRegistrationAndDelegation
  , certificate_kind
  , certificate_asStakeRegistration
  , certificate_asStakeDeregistration
  , certificate_asStakeDelegation
  , certificate_asPoolRegistration
  , certificate_asPoolRetirement
  , certificate_asGenesisKeyDelegation
  , certificate_asMoveInstantaneousRewardsCert
  , certificate_asCommitteeHotAuth
  , certificate_asCommitteeColdResign
  , certificate_asDrepDeregistration
  , certificate_asDrepRegistration
  , certificate_asDrepUpdate
  , certificate_asStakeAndVoteDelegation
  , certificate_asStakeRegistrationAndDelegation
  , certificate_asStakeVoteRegistrationAndDelegation
  , certificate_asVoteDelegation
  , certificate_asVoteRegistrationAndDelegation
  , certificate_hasRequiredScriptWitness
  , certificates_new
  , changeConfig_new
  , changeConfig_changeAddress
  , changeConfig_changePlutusData
  , changeConfig_changeScriptRef
  , committee_new
  , committee_membersKeys
  , committee_quorumThreshold
  , committee_addMember
  , committee_getMemberEpoch
  , committeeColdResign_committeeColdKey
  , committeeColdResign_anchor
  , committeeColdResign_new
  , committeeColdResign_newWithAnchor
  , committeeColdResign_hasScriptCredentials
  , committeeHotAuth_committeeColdKey
  , committeeHotAuth_committeeHotKey
  , committeeHotAuth_new
  , committeeHotAuth_hasScriptCredentials
  , constitution_anchor
  , constitution_scriptHash
  , constitution_new
  , constitution_newWithScriptHash
  , constrPlutusData_alternative
  , constrPlutusData_data
  , constrPlutusData_new
  , costModel_free
  , costModel_toBytes
  , costModel_fromBytes
  , costModel_toHex
  , costModel_fromHex
  , costModel_toJson
  , costModel_fromJson
  , costModel_new
  , costModel_set
  , costModel_get
  , costModel_len
  , costmdls_new
  , costmdls_retainLanguageVersions
  , credential_fromKeyhash
  , credential_fromScripthash
  , credential_toKeyhash
  , credential_toScripthash
  , credential_kind
  , credential_hasScriptHash
  , credentials_new
  , dnsRecordAorAAAA_new
  , dnsRecordAorAAAA_record
  , dnsRecordSRV_new
  , dnsRecordSRV_record
  , dRep_newKeyHash
  , dRep_newScriptHash
  , dRep_newAlwaysAbstain
  , dRep_newAlwaysNoConfidence
  , dRep_kind
  , dRep_toKeyHash
  , dRep_toScriptHash
  , dataCost_newCoinsPerByte
  , dataCost_coinsPerByte
  , dataHash_toBech32
  , dataHash_fromBech32
  , datumSource_new
  , datumSource_newRefInput
  , drepDeregistration_votingCredential
  , drepDeregistration_coin
  , drepDeregistration_new
  , drepDeregistration_hasScriptCredentials
  , drepRegistration_votingCredential
  , drepRegistration_coin
  , drepRegistration_anchor
  , drepRegistration_new
  , drepRegistration_newWithAnchor
  , drepRegistration_hasScriptCredentials
  , drepUpdate_votingCredential
  , drepUpdate_anchor
  , drepUpdate_new
  , drepUpdate_newWithAnchor
  , drepUpdate_hasScriptCredentials
  , drepVotingThresholds_new
  , drepVotingThresholds_newDefault
  , drepVotingThresholds_setMotionNoConfidence
  , drepVotingThresholds_setCommitteeNormal
  , drepVotingThresholds_setCommitteeNoConfidence
  , drepVotingThresholds_setUpdateConstitution
  , drepVotingThresholds_setHardForkInitiation
  , drepVotingThresholds_setPpNetworkGroup
  , drepVotingThresholds_setPpEconomicGroup
  , drepVotingThresholds_setPpTechnicalGroup
  , drepVotingThresholds_setPpGovernanceGroup
  , drepVotingThresholds_setTreasuryWithdrawal
  , drepVotingThresholds_motionNoConfidence
  , drepVotingThresholds_committeeNormal
  , drepVotingThresholds_committeeNoConfidence
  , drepVotingThresholds_updateConstitution
  , drepVotingThresholds_hardForkInitiation
  , drepVotingThresholds_ppNetworkGroup
  , drepVotingThresholds_ppEconomicGroup
  , drepVotingThresholds_ppTechnicalGroup
  , drepVotingThresholds_ppGovernanceGroup
  , drepVotingThresholds_treasuryWithdrawal
  , ed25519KeyHash_toBech32
  , ed25519KeyHash_fromBech32
  , ed25519KeyHashes_new
  , ed25519KeyHashes_contains
  , ed25519KeyHashes_toOption
  , ed25519Signature_toBech32
  , ed25519Signature_fromBech32
  , enterpriseAddress_new
  , enterpriseAddress_paymentCred
  , enterpriseAddress_toAddress
  , enterpriseAddress_fromAddress
  , exUnitPrices_memPrice
  , exUnitPrices_stepPrice
  , exUnitPrices_new
  , exUnits_mem
  , exUnits_steps
  , exUnits_new
  , generalTransactionMetadata_new
  , genesisDelegateHash_toBech32
  , genesisDelegateHash_fromBech32
  , genesisHash_toBech32
  , genesisHash_fromBech32
  , genesisHashes_new
  , genesisKeyDelegation_genesishash
  , genesisKeyDelegation_genesisDelegateHash
  , genesisKeyDelegation_vrfKeyhash
  , genesisKeyDelegation_new
  , governanceAction_newParameterChangeAction
  , governanceAction_newHardForkInitiationAction
  , governanceAction_newTreasuryWithdrawalsAction
  , governanceAction_newNoConfidenceAction
  , governanceAction_newNewCommitteeAction
  , governanceAction_newNewConstitutionAction
  , governanceAction_newInfoAction
  , governanceAction_kind
  , governanceAction_asParameterChangeAction
  , governanceAction_asHardForkInitiationAction
  , governanceAction_asTreasuryWithdrawalsAction
  , governanceAction_asNoConfidenceAction
  , governanceAction_asNewCommitteeAction
  , governanceAction_asNewConstitutionAction
  , governanceAction_asInfoAction
  , governanceActionId_transactionId
  , governanceActionId_index
  , governanceActionId_new
  , governanceActionIds_new
  , hardForkInitiationAction_govActionId
  , hardForkInitiationAction_protocolVersion
  , hardForkInitiationAction_new
  , hardForkInitiationAction_newWithActionId
  , infoAction_new
  , int_new
  , int_newNegative
  , int_newI32
  , int_isPositive
  , int_asPositive
  , int_asNegative
  , int_asI32
  , int_asI32OrNothing
  , int_asI32OrFail
  , int_toStr
  , int_fromStr
  , ipv4_new
  , ipv4_ip
  , ipv6_new
  , ipv6_ip
  , kesvKey_toBech32
  , kesvKey_fromBech32
  , language_newPlutusV1
  , language_newPlutusV2
  , language_newPlutusV3
  , language_kind
  , languages_new
  , languages_list
  , legacyDaedalusPrivateKey_asBytes
  , legacyDaedalusPrivateKey_chaincode
  , linearFee_constant
  , linearFee_coefficient
  , linearFee_new
  , mirToStakeCredentials_new
  , malformedAddress_originalBytes
  , malformedAddress_toAddress
  , malformedAddress_fromAddress
  , metadataList_new
  , metadataMap_new
  , metadataMap_insertStr
  , metadataMap_insertI32
  , metadataMap_getStr
  , metadataMap_getI32
  , metadataMap_has
  , mint_new
  , mint_newFromEntry
  , mint_asPositiveMultiasset
  , mint_asNegativeMultiasset
  , mintAssets_new
  , mintAssets_newFromEntry
  , mintWitness_newNativeScript
  , mintWitness_newPlutusScript
  , mintsAssets_new
  , moveInstantaneousReward_newToOtherPot
  , moveInstantaneousReward_newToStakeCreds
  , moveInstantaneousReward_pot
  , moveInstantaneousReward_kind
  , moveInstantaneousReward_asToOtherPot
  , moveInstantaneousReward_asToStakeCreds
  , moveInstantaneousRewardsCert_moveInstantaneousReward
  , moveInstantaneousRewardsCert_new
  , multiAsset_new
  , multiAsset_setAsset
  , multiAsset_getAsset
  , multiAsset_sub
  , multiHostName_dnsName
  , multiHostName_new
  , nativeScript_hash
  , nativeScript_newScriptPubkey
  , nativeScript_newScriptAll
  , nativeScript_newScriptAny
  , nativeScript_newScriptNOfK
  , nativeScript_newTimelockStart
  , nativeScript_newTimelockExpiry
  , nativeScript_kind
  , nativeScript_asScriptPubkey
  , nativeScript_asScriptAll
  , nativeScript_asScriptAny
  , nativeScript_asScriptNOfK
  , nativeScript_asTimelockStart
  , nativeScript_asTimelockExpiry
  , nativeScript_getRequiredSigners
  , nativeScriptSource_new
  , nativeScriptSource_newRefInput
  , nativeScriptSource_setRequiredSigners
  , nativeScripts_new
  , networkId_testnet
  , networkId_mainnet
  , networkId_kind
  , networkInfo_new
  , networkInfo_networkId
  , networkInfo_protocolMagic
  , networkInfo_testnetPreview
  , networkInfo_testnetPreprod
  , networkInfo_mainnet
  , newConstitutionAction_govActionId
  , newConstitutionAction_constitution
  , newConstitutionAction_new
  , newConstitutionAction_newWithActionId
  , newConstitutionAction_hasScriptHash
  , noConfidenceAction_govActionId
  , noConfidenceAction_new
  , noConfidenceAction_newWithActionId
  , nonce_newIdentity
  , nonce_newFromHash
  , nonce_getHash
  , operationalCert_hotVkey
  , operationalCert_sequenceNumber
  , operationalCert_kesPeriod
  , operationalCert_sigma
  , operationalCert_new
  , outputDatum_newDataHash
  , outputDatum_newData
  , outputDatum_dataHash
  , outputDatum_data
  , parameterChangeAction_govActionId
  , parameterChangeAction_protocolParamUpdates
  , parameterChangeAction_policyHash
  , parameterChangeAction_new
  , parameterChangeAction_newWithActionId
  , parameterChangeAction_newWithPolicyHash
  , parameterChangeAction_newWithPolicyHashAndActionId
  , plutusData_newConstrPlutusData
  , plutusData_newEmptyConstrPlutusData
  , plutusData_newSingleValueConstrPlutusData
  , plutusData_newMap
  , plutusData_newList
  , plutusData_newInteger
  , plutusData_newBytes
  , plutusData_kind
  , plutusData_asConstrPlutusData
  , plutusData_asMap
  , plutusData_asList
  , plutusData_asInteger
  , plutusData_asBytes
  , plutusData_fromAddress
  , plutusList_new
  , plutusMap_new
  , plutusScript_new
  , plutusScript_newV2
  , plutusScript_newV3
  , plutusScript_newWithVersion
  , plutusScript_bytes
  , plutusScript_fromBytesV2
  , plutusScript_fromBytesV3
  , plutusScript_fromBytesWithVersion
  , plutusScript_fromHexWithVersion
  , plutusScript_hash
  , plutusScript_languageVersion
  , plutusScriptSource_new
  , plutusScriptSource_newRefInput
  , plutusScriptSource_setRequiredSigners
  , plutusScriptSource_getRefScriptSize
  , plutusScripts_new
  , plutusWitness_new
  , plutusWitness_newWithRef
  , plutusWitness_newWithoutDatum
  , plutusWitness_newWithRefWithoutDatum
  , plutusWitness_script
  , plutusWitness_datum
  , plutusWitness_redeemer
  , plutusWitnesses_new
  , pointer_new
  , pointer_newPointer
  , pointer_slot
  , pointer_txIndex
  , pointer_certIndex
  , pointer_slotBignum
  , pointer_txIndexBignum
  , pointer_certIndexBignum
  , pointerAddress_new
  , pointerAddress_paymentCred
  , pointerAddress_stakePointer
  , pointerAddress_toAddress
  , pointerAddress_fromAddress
  , poolMetadata_url
  , poolMetadata_poolMetadataHash
  , poolMetadata_new
  , poolMetadataHash_toBech32
  , poolMetadataHash_fromBech32
  , poolParams_operator
  , poolParams_vrfKeyhash
  , poolParams_pledge
  , poolParams_cost
  , poolParams_margin
  , poolParams_rewardAccount
  , poolParams_poolOwners
  , poolParams_relays
  , poolParams_poolMetadata
  , poolParams_new
  , poolRegistration_poolParams
  , poolRegistration_new
  , poolRetirement_poolKeyhash
  , poolRetirement_epoch
  , poolRetirement_new
  , poolVotingThresholds_new
  , poolVotingThresholds_motionNoConfidence
  , poolVotingThresholds_committeeNormal
  , poolVotingThresholds_committeeNoConfidence
  , poolVotingThresholds_hardForkInitiation
  , poolVotingThresholds_securityRelevantThreshold
  , privateKey_free
  , privateKey_fromHex
  , privateKey_toHex
  , privateKey_sign
  , privateKey_fromNormalBytes
  , privateKey_fromExtendedBytes
  , privateKey_asBytes
  , privateKey_toBech32
  , privateKey_fromBech32
  , privateKey_generateEd25519extended
  , privateKey_generateEd25519
  , privateKey_toPublic
  , proposedProtocolParameterUpdates_new
  , protocolParamUpdate_setMinfeeA
  , protocolParamUpdate_minfeeA
  , protocolParamUpdate_setMinfeeB
  , protocolParamUpdate_minfeeB
  , protocolParamUpdate_setMaxBlockBodySize
  , protocolParamUpdate_maxBlockBodySize
  , protocolParamUpdate_setMaxTxSize
  , protocolParamUpdate_maxTxSize
  , protocolParamUpdate_setMaxBlockHeaderSize
  , protocolParamUpdate_maxBlockHeaderSize
  , protocolParamUpdate_setKeyDeposit
  , protocolParamUpdate_keyDeposit
  , protocolParamUpdate_setPoolDeposit
  , protocolParamUpdate_poolDeposit
  , protocolParamUpdate_setMaxEpoch
  , protocolParamUpdate_maxEpoch
  , protocolParamUpdate_setNOpt
  , protocolParamUpdate_nOpt
  , protocolParamUpdate_setPoolPledgeInfluence
  , protocolParamUpdate_poolPledgeInfluence
  , protocolParamUpdate_setExpansionRate
  , protocolParamUpdate_expansionRate
  , protocolParamUpdate_setTreasuryGrowthRate
  , protocolParamUpdate_treasuryGrowthRate
  , protocolParamUpdate_d
  , protocolParamUpdate_extraEntropy
  , protocolParamUpdate_setProtocolVersion
  , protocolParamUpdate_protocolVersion
  , protocolParamUpdate_setMinPoolCost
  , protocolParamUpdate_minPoolCost
  , protocolParamUpdate_setAdaPerUtxoByte
  , protocolParamUpdate_adaPerUtxoByte
  , protocolParamUpdate_setCostModels
  , protocolParamUpdate_costModels
  , protocolParamUpdate_setExecutionCosts
  , protocolParamUpdate_executionCosts
  , protocolParamUpdate_setMaxTxExUnits
  , protocolParamUpdate_maxTxExUnits
  , protocolParamUpdate_setMaxBlockExUnits
  , protocolParamUpdate_maxBlockExUnits
  , protocolParamUpdate_setMaxValueSize
  , protocolParamUpdate_maxValueSize
  , protocolParamUpdate_setCollateralPercentage
  , protocolParamUpdate_collateralPercentage
  , protocolParamUpdate_setMaxCollateralInputs
  , protocolParamUpdate_maxCollateralInputs
  , protocolParamUpdate_setPoolVotingThresholds
  , protocolParamUpdate_poolVotingThresholds
  , protocolParamUpdate_setDrepVotingThresholds
  , protocolParamUpdate_drepVotingThresholds
  , protocolParamUpdate_setMinCommitteeSize
  , protocolParamUpdate_minCommitteeSize
  , protocolParamUpdate_setCommitteeTermLimit
  , protocolParamUpdate_committeeTermLimit
  , protocolParamUpdate_setGovernanceActionValidityPeriod
  , protocolParamUpdate_governanceActionValidityPeriod
  , protocolParamUpdate_setGovernanceActionDeposit
  , protocolParamUpdate_governanceActionDeposit
  , protocolParamUpdate_setDrepDeposit
  , protocolParamUpdate_drepDeposit
  , protocolParamUpdate_setDrepInactivityPeriod
  , protocolParamUpdate_drepInactivityPeriod
  , protocolParamUpdate_setRefScriptCoinsPerByte
  , protocolParamUpdate_refScriptCoinsPerByte
  , protocolParamUpdate_new
  , protocolVersion_major
  , protocolVersion_minor
  , protocolVersion_new
  , publicKey_free
  , publicKey_fromHex
  , publicKey_toHex
  , publicKey_hash
  , publicKey_verify
  , publicKey_fromBytes
  , publicKey_asBytes
  , publicKey_toBech32
  , publicKey_fromBech32
  , redeemer_tag
  , redeemer_index
  , redeemer_data
  , redeemer_exUnits
  , redeemer_new
  , redeemerTag_newSpend
  , redeemerTag_newMint
  , redeemerTag_newCert
  , redeemerTag_newReward
  , redeemerTag_newVote
  , redeemerTag_newVotingProposal
  , redeemerTag_kind
  , redeemers_new
  , redeemers_totalExUnits
  , relay_newSingleHostAddr
  , relay_newSingleHostName
  , relay_newMultiHostName
  , relay_kind
  , relay_asSingleHostAddr
  , relay_asSingleHostName
  , relay_asMultiHostName
  , relays_new
  , rewardAddress_new
  , rewardAddress_paymentCred
  , rewardAddress_toAddress
  , rewardAddress_fromAddress
  , rewardAddresses_new
  , scriptAll_nativeScripts
  , scriptAll_new
  , scriptAny_nativeScripts
  , scriptAny_new
  , scriptDataHash_toBech32
  , scriptDataHash_fromBech32
  , scriptHash_toBech32
  , scriptHash_fromBech32
  , scriptHashes_new
  , scriptNOfK_n
  , scriptNOfK_nativeScripts
  , scriptNOfK_new
  , scriptPubkey_addrKeyhash
  , scriptPubkey_new
  , scriptRef_newNativeScript
  , scriptRef_newPlutusScript
  , scriptRef_isNativeScript
  , scriptRef_isPlutusScript
  , scriptRef_nativeScript
  , scriptRef_plutusScript
  , singleHostAddr_port
  , singleHostAddr_ipv4
  , singleHostAddr_ipv6
  , singleHostAddr_new
  , singleHostName_port
  , singleHostName_dnsName
  , singleHostName_new
  , stakeAndVoteDelegation_stakeCredential
  , stakeAndVoteDelegation_poolKeyhash
  , stakeAndVoteDelegation_drep
  , stakeAndVoteDelegation_new
  , stakeAndVoteDelegation_hasScriptCredentials
  , stakeDelegation_stakeCredential
  , stakeDelegation_poolKeyhash
  , stakeDelegation_new
  , stakeDelegation_hasScriptCredentials
  , stakeDeregistration_stakeCredential
  , stakeDeregistration_coin
  , stakeDeregistration_new
  , stakeDeregistration_newWithCoin
  , stakeDeregistration_hasScriptCredentials
  , stakeRegistration_stakeCredential
  , stakeRegistration_coin
  , stakeRegistration_new
  , stakeRegistration_newWithCoin
  , stakeRegistration_hasScriptCredentials
  , stakeRegistrationAndDelegation_stakeCredential
  , stakeRegistrationAndDelegation_poolKeyhash
  , stakeRegistrationAndDelegation_coin
  , stakeRegistrationAndDelegation_new
  , stakeRegistrationAndDelegation_hasScriptCredentials
  , stakeVoteRegistrationAndDelegation_stakeCredential
  , stakeVoteRegistrationAndDelegation_poolKeyhash
  , stakeVoteRegistrationAndDelegation_drep
  , stakeVoteRegistrationAndDelegation_coin
  , stakeVoteRegistrationAndDelegation_new
  , stakeVoteRegistrationAndDelegation_hasScriptCredentials
  , timelockExpiry_slot
  , timelockExpiry_slotBignum
  , timelockExpiry_new
  , timelockExpiry_newTimelockexpiry
  , timelockStart_slot
  , timelockStart_slotBignum
  , timelockStart_new
  , timelockStart_newTimelockstart
  , transaction_body
  , transaction_witnessSet
  , transaction_isValid
  , transaction_auxiliaryData
  , transaction_setIsValid
  , transaction_new
  , transactionBody_inputs
  , transactionBody_outputs
  , transactionBody_fee
  , transactionBody_ttl
  , transactionBody_ttlBignum
  , transactionBody_setTtl
  , transactionBody_removeTtl
  , transactionBody_setCerts
  , transactionBody_certs
  , transactionBody_setWithdrawals
  , transactionBody_withdrawals
  , transactionBody_setUpdate
  , transactionBody_update
  , transactionBody_setAuxiliaryDataHash
  , transactionBody_auxiliaryDataHash
  , transactionBody_setValidityStartInterval
  , transactionBody_setValidityStartIntervalBignum
  , transactionBody_validityStartIntervalBignum
  , transactionBody_validityStartInterval
  , transactionBody_setMint
  , transactionBody_mint
  , transactionBody_setReferenceInputs
  , transactionBody_referenceInputs
  , transactionBody_setScriptDataHash
  , transactionBody_scriptDataHash
  , transactionBody_setCollateral
  , transactionBody_collateral
  , transactionBody_setRequiredSigners
  , transactionBody_requiredSigners
  , transactionBody_setNetworkId
  , transactionBody_networkId
  , transactionBody_setCollateralReturn
  , transactionBody_collateralReturn
  , transactionBody_setTotalCollateral
  , transactionBody_totalCollateral
  , transactionBody_setVotingProcedures
  , transactionBody_votingProcedures
  , transactionBody_setVotingProposals
  , transactionBody_votingProposals
  , transactionBody_setDonation
  , transactionBody_donation
  , transactionBody_setCurrentTreasuryValue
  , transactionBody_currentTreasuryValue
  , transactionBody_new
  , transactionBody_newTxBody
  , transactionHash_toBech32
  , transactionHash_fromBech32
  , transactionInput_transactionId
  , transactionInput_index
  , transactionInput_new
  , transactionInputs_new
  , transactionInputs_toOption
  , transactionMetadatum_newMap
  , transactionMetadatum_newList
  , transactionMetadatum_newInt
  , transactionMetadatum_newBytes
  , transactionMetadatum_newText
  , transactionMetadatum_kind
  , transactionMetadatum_asMap
  , transactionMetadatum_asList
  , transactionMetadatum_asInt
  , transactionMetadatum_asBytes
  , transactionMetadatum_asText
  , transactionMetadatumLabels_new
  , transactionOutput_address
  , transactionOutput_amount
  , transactionOutput_dataHash
  , transactionOutput_plutusData
  , transactionOutput_scriptRef
  , transactionOutput_setScriptRef
  , transactionOutput_setPlutusData
  , transactionOutput_setDataHash
  , transactionOutput_hasPlutusData
  , transactionOutput_hasDataHash
  , transactionOutput_hasScriptRef
  , transactionOutput_new
  , transactionOutput_serializationFormat
  , transactionOutputs_new
  , transactionUnspentOutput_new
  , transactionUnspentOutput_input
  , transactionUnspentOutput_output
  , transactionUnspentOutputs_new
  , transactionWitnessSet_setVkeys
  , transactionWitnessSet_vkeys
  , transactionWitnessSet_setNativeScripts
  , transactionWitnessSet_nativeScripts
  , transactionWitnessSet_setBootstraps
  , transactionWitnessSet_bootstraps
  , transactionWitnessSet_setPlutusScripts
  , transactionWitnessSet_plutusScripts
  , transactionWitnessSet_setPlutusData
  , transactionWitnessSet_plutusData
  , transactionWitnessSet_setRedeemers
  , transactionWitnessSet_redeemers
  , transactionWitnessSet_new
  , treasuryWithdrawals_new
  , treasuryWithdrawalsAction_withdrawals
  , treasuryWithdrawalsAction_policyHash
  , treasuryWithdrawalsAction_new
  , treasuryWithdrawalsAction_newWithPolicyHash
  , url_new
  , url_url
  , unitInterval_numerator
  , unitInterval_denominator
  , unitInterval_new
  , update_proposedProtocolParameterUpdates
  , update_epoch
  , update_new
  , updateCommitteeAction_govActionId
  , updateCommitteeAction_committee
  , updateCommitteeAction_membersToRemove
  , updateCommitteeAction_new
  , updateCommitteeAction_newWithActionId
  , vrfCert_output
  , vrfCert_proof
  , vrfCert_new
  , vrfKeyHash_toBech32
  , vrfKeyHash_fromBech32
  , vrfvKey_toBech32
  , vrfvKey_fromBech32
  , value_new
  , value_newFromAssets
  , value_newWithAssets
  , value_zero
  , value_isZero
  , value_coin
  , value_setCoin
  , value_multiasset
  , value_setMultiasset
  , value_checkedAdd
  , value_checkedSub
  , value_clampedSub
  , value_compare
  , vkey_new
  , vkey_publicKey
  , vkeys_new
  , vkeywitness_new
  , vkeywitness_vkey
  , vkeywitness_signature
  , vkeywitnesses_new
  , voteDelegation_stakeCredential
  , voteDelegation_drep
  , voteDelegation_new
  , voteDelegation_hasScriptCredentials
  , voteRegistrationAndDelegation_stakeCredential
  , voteRegistrationAndDelegation_drep
  , voteRegistrationAndDelegation_coin
  , voteRegistrationAndDelegation_new
  , voteRegistrationAndDelegation_hasScriptCredentials
  , voter_newConstitutionalCommitteeHotKey
  , voter_newDrep
  , voter_newStakingPool
  , voter_kind
  , voter_toConstitutionalCommitteeHotCred
  , voter_toDrepCred
  , voter_toStakingPoolKeyHash
  , voter_hasScriptCredentials
  , voter_toKeyHash
  , voters_new
  , votingProcedure_new
  , votingProcedure_newWithAnchor
  , votingProcedure_voteKind
  , votingProcedure_anchor
  , votingProcedures_free
  , votingProcedures_toBytes
  , votingProcedures_fromBytes
  , votingProcedures_toHex
  , votingProcedures_fromHex
  , votingProcedures_toJson
  , votingProcedures_fromJson
  , votingProcedures_new
  , votingProcedures_insert
  , votingProcedures_get
  , votingProcedures_getVoters
  , votingProcedures_getGovernanceActionIdsByVoter
  , votingProposal_governanceAction
  , votingProposal_anchor
  , votingProposal_rewardAccount
  , votingProposal_deposit
  , votingProposal_new
  , votingProposals_new
  , withdrawals_new
  , makeVkeyWitness
  , hashAuxiliaryData
  , hashTransaction
  , hashPlutusData
  , hashScriptData
  , minAdaForOutput
  , minFee
  , minScriptFee
  , minRefScriptFee
  , Address
  , Anchor
  , AnchorDataHash
  , AssetName
  , AssetNames
  , Assets
  , AuxiliaryData
  , AuxiliaryDataHash
  , BaseAddress
  , BigInt
  , BigNum
  , Bip32PrivateKey
  , Bip32PublicKey
  , BlockHash
  , BootstrapWitness
  , BootstrapWitnesses
  , ByronAddress
  , Certificate
  , Certificates
  , ChangeConfig
  , Committee
  , CommitteeColdResign
  , CommitteeHotAuth
  , Constitution
  , ConstrPlutusData
  , CostModel
  , Costmdls
  , Credential
  , Credentials
  , DNSRecordAorAAAA
  , DNSRecordSRV
  , DRep
  , DataCost
  , DataHash
  , DatumSource
  , DrepDeregistration
  , DrepRegistration
  , DrepUpdate
  , DrepVotingThresholds
  , Ed25519KeyHash
  , Ed25519KeyHashes
  , Ed25519Signature
  , EnterpriseAddress
  , ExUnitPrices
  , ExUnits
  , GeneralTransactionMetadata
  , GenesisDelegateHash
  , GenesisHash
  , GenesisHashes
  , GenesisKeyDelegation
  , GovernanceAction
  , GovernanceActionId
  , GovernanceActionIds
  , HardForkInitiationAction
  , InfoAction
  , Int
  , Ipv4
  , Ipv6
  , KESSignature
  , KESVKey
  , Language
  , Languages
  , LegacyDaedalusPrivateKey
  , LinearFee
  , MIRToStakeCredentials
  , MalformedAddress
  , MetadataList
  , MetadataMap
  , Mint
  , MintAssets
  , MintWitness
  , MintsAssets
  , MoveInstantaneousReward
  , MoveInstantaneousRewardsCert
  , MultiAsset
  , MultiHostName
  , NativeScript
  , NativeScriptSource
  , NativeScripts
  , NetworkId
  , NetworkInfo
  , NewConstitutionAction
  , NoConfidenceAction
  , Nonce
  , OperationalCert
  , OutputDatum
  , ParameterChangeAction
  , PlutusData
  , PlutusList
  , PlutusMap
  , PlutusScript
  , PlutusScriptSource
  , PlutusScripts
  , PlutusWitness
  , PlutusWitnesses
  , Pointer
  , PointerAddress
  , PoolMetadata
  , PoolMetadataHash
  , PoolParams
  , PoolRegistration
  , PoolRetirement
  , PoolVotingThresholds
  , PrivateKey
  , ProposedProtocolParameterUpdates
  , ProtocolParamUpdate
  , ProtocolVersion
  , PublicKey
  , Redeemer
  , RedeemerTag
  , Redeemers
  , Relay
  , Relays
  , RewardAddress
  , RewardAddresses
  , ScriptAll
  , ScriptAny
  , ScriptDataHash
  , ScriptHash
  , ScriptHashes
  , ScriptNOfK
  , ScriptPubkey
  , ScriptRef
  , SingleHostAddr
  , SingleHostName
  , StakeAndVoteDelegation
  , StakeDelegation
  , StakeDeregistration
  , StakeRegistration
  , StakeRegistrationAndDelegation
  , StakeVoteRegistrationAndDelegation
  , TimelockExpiry
  , TimelockStart
  , Transaction
  , TransactionBatch
  , TransactionBatchList
  , TransactionBody
  , TransactionHash
  , TransactionInput
  , TransactionInputs
  , TransactionMetadatum
  , TransactionMetadatumLabels
  , TransactionOutput
  , TransactionOutputs
  , TransactionUnspentOutput
  , TransactionUnspentOutputs
  , TransactionWitnessSet
  , TreasuryWithdrawals
  , TreasuryWithdrawalsAction
  , URL
  , UnitInterval
  , Update
  , UpdateCommitteeAction
  , VRFCert
  , VRFKeyHash
  , VRFVKey
  , Value
  , Vkey
  , Vkeys
  , Vkeywitness
  , Vkeywitnesses
  , VoteDelegation
  , VoteRegistrationAndDelegation
  , Voter
  , Voters
  , VotingProcedure
  , VotingProcedures
  , VotingProposal
  , VotingProposals
  , Withdrawals
  , RedeemerTagKind
  , CoinSelectionStrategyCIP2
  , VoteKind
  , VoterKind
  , RelayKind
  , ScriptSchema
  , GovernanceActionKind
  , AddressKind
  , PlutusDatumSchema
  , CredKind
  , MIRKind
  , NetworkIdKind
  , CborContainerType
  , MIRPot
  , ScriptHashNamespace
  , LanguageKind
  , NativeScriptKind
  , TransactionMetadatumKind
  , PlutusDataKind
  , CertificateKind
  , MetadataJsonSchema
  , DRepKind
  , RedeemerTagKindValues(..)
  , CoinSelectionStrategyCIP2Values(..)
  , VoteKindValues(..)
  , VoterKindValues(..)
  , RelayKindValues(..)
  , ScriptSchemaValues(..)
  , GovernanceActionKindValues(..)
  , AddressKindValues(..)
  , PlutusDatumSchemaValues(..)
  , CredKindValues(..)
  , MIRKindValues(..)
  , NetworkIdKindValues(..)
  , CborContainerTypeValues(..)
  , MIRPotValues(..)
  , ScriptHashNamespaceValues(..)
  , LanguageKindValues(..)
  , NativeScriptKindValues(..)
  , TransactionMetadatumKindValues(..)
  , PlutusDataKindValues(..)
  , CertificateKindValues(..)
  , MetadataJsonSchemaValues(..)
  , DRepKindValues(..)
  ) where

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
  , packMultiMapContainerFromMap
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

-- functions
-- | Make vkey witness
-- > makeVkeyWitness txBodyHash sk
foreign import makeVkeyWitness :: TransactionHash -> PrivateKey -> Vkeywitness

-- | Hash auxiliary data
-- > hashAuxiliaryData auxiliaryData
foreign import hashAuxiliaryData :: AuxiliaryData -> AuxiliaryDataHash

-- | Hash transaction
-- > hashTransaction txBody
foreign import hashTransaction :: TransactionBody -> TransactionHash

-- | Hash plutus data
-- > hashPlutusData plutusData
foreign import hashPlutusData :: PlutusData -> DataHash

-- | Hash script data
-- > hashScriptData redeemers costModels datums
foreign import hashScriptData :: Redeemers -> Costmdls -> PlutusList -> ScriptDataHash

-- | Min ada for output
-- > minAdaForOutput output dataCost
foreign import minAdaForOutput :: TransactionOutput -> DataCost -> BigNum

-- | Min fee
-- > minFee tx linearFee
foreign import minFee :: Transaction -> LinearFee -> BigNum

-- | Min script fee
-- > minScriptFee tx exUnitPrices
foreign import minScriptFee :: Transaction -> ExUnitPrices -> BigNum

-- | Min ref script fee
-- > minRefScriptFee totalRefScriptsSize refScriptCoinsPerByte
foreign import minRefScriptFee :: Number -> UnitInterval -> BigNum

-- classes

--------------------------------------------------------------------------------
-- Address

foreign import data Address :: Type

foreign import address_kind :: Address -> AddressKind
foreign import address_paymentCred :: Address -> Nullable Credential
foreign import address_isMalformed :: Address -> Boolean
foreign import address_toBech32 :: Address -> String -> String
foreign import address_fromBech32 :: String -> Nullable Address
foreign import address_networkId :: Address -> Number

instance IsCsl Address where
  className _ = "Address"

instance IsBytes Address
instance IsJson Address
instance EncodeAeson Address where
  encodeAeson = cslToAeson

instance DecodeAeson Address where
  decodeAeson = cslFromAeson

instance Show Address where
  show = showViaJson

--------------------------------------------------------------------------------
-- Anchor

foreign import data Anchor :: Type

foreign import anchor_url :: Anchor -> URL
foreign import anchor_anchorDataHash :: Anchor -> AnchorDataHash
foreign import anchor_new :: URL -> AnchorDataHash -> Anchor

instance IsCsl Anchor where
  className _ = "Anchor"

instance IsBytes Anchor
instance IsJson Anchor
instance EncodeAeson Anchor where
  encodeAeson = cslToAeson

instance DecodeAeson Anchor where
  decodeAeson = cslFromAeson

instance Show Anchor where
  show = showViaJson

--------------------------------------------------------------------------------
-- Anchor data hash

foreign import data AnchorDataHash :: Type

foreign import anchorDataHash_toBech32 :: AnchorDataHash -> String -> String
foreign import anchorDataHash_fromBech32 :: String -> Nullable AnchorDataHash

instance IsCsl AnchorDataHash where
  className _ = "AnchorDataHash"

instance IsBytes AnchorDataHash
instance EncodeAeson AnchorDataHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson AnchorDataHash where
  decodeAeson = cslFromAesonViaBytes

instance Show AnchorDataHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Asset name

foreign import data AssetName :: Type

foreign import assetName_new :: ByteArray -> AssetName
foreign import assetName_name :: AssetName -> ByteArray

instance IsCsl AssetName where
  className _ = "AssetName"

instance IsBytes AssetName
instance IsJson AssetName
instance EncodeAeson AssetName where
  encodeAeson = cslToAeson

instance DecodeAeson AssetName where
  decodeAeson = cslFromAeson

instance Show AssetName where
  show = showViaJson

--------------------------------------------------------------------------------
-- Asset names

foreign import data AssetNames :: Type

foreign import assetNames_new :: Effect AssetNames

instance IsCsl AssetNames where
  className _ = "AssetNames"

instance IsBytes AssetNames
instance IsJson AssetNames
instance EncodeAeson AssetNames where
  encodeAeson = cslToAeson

instance DecodeAeson AssetNames where
  decodeAeson = cslFromAeson

instance Show AssetNames where
  show = showViaJson

instance IsListContainer AssetNames AssetName

--------------------------------------------------------------------------------
-- Assets

foreign import data Assets :: Type

foreign import assets_new :: Effect Assets

instance IsCsl Assets where
  className _ = "Assets"

instance IsBytes Assets
instance IsJson Assets
instance EncodeAeson Assets where
  encodeAeson = cslToAeson

instance DecodeAeson Assets where
  decodeAeson = cslFromAeson

instance Show Assets where
  show = showViaJson

instance IsMapContainer Assets AssetName BigNum

--------------------------------------------------------------------------------
-- Auxiliary data

foreign import data AuxiliaryData :: Type

foreign import auxiliaryData_new :: Effect AuxiliaryData
foreign import auxiliaryData_metadata :: AuxiliaryData -> Nullable GeneralTransactionMetadata
foreign import auxiliaryData_setMetadata :: AuxiliaryData -> GeneralTransactionMetadata -> Effect Unit
foreign import auxiliaryData_nativeScripts :: AuxiliaryData -> Nullable NativeScripts
foreign import auxiliaryData_setNativeScripts :: AuxiliaryData -> NativeScripts -> Effect Unit
foreign import auxiliaryData_plutusScripts :: AuxiliaryData -> Nullable PlutusScripts
foreign import auxiliaryData_setPlutusScripts :: AuxiliaryData -> PlutusScripts -> Effect Unit
foreign import auxiliaryData_preferAlonzoFormat :: AuxiliaryData -> Boolean
foreign import auxiliaryData_setPreferAlonzoFormat :: AuxiliaryData -> Boolean -> Effect Unit

instance IsCsl AuxiliaryData where
  className _ = "AuxiliaryData"

instance IsBytes AuxiliaryData
instance IsJson AuxiliaryData
instance EncodeAeson AuxiliaryData where
  encodeAeson = cslToAeson

instance DecodeAeson AuxiliaryData where
  decodeAeson = cslFromAeson

instance Show AuxiliaryData where
  show = showViaJson

--------------------------------------------------------------------------------
-- Auxiliary data hash

foreign import data AuxiliaryDataHash :: Type

foreign import auxiliaryDataHash_toBech32 :: AuxiliaryDataHash -> String -> String
foreign import auxiliaryDataHash_fromBech32 :: String -> Nullable AuxiliaryDataHash

instance IsCsl AuxiliaryDataHash where
  className _ = "AuxiliaryDataHash"

instance IsBytes AuxiliaryDataHash
instance EncodeAeson AuxiliaryDataHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson AuxiliaryDataHash where
  decodeAeson = cslFromAesonViaBytes

instance Show AuxiliaryDataHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Base address

foreign import data BaseAddress :: Type

foreign import baseAddress_new :: Number -> Credential -> Credential -> BaseAddress
foreign import baseAddress_paymentCred :: BaseAddress -> Credential
foreign import baseAddress_stakeCred :: BaseAddress -> Credential
foreign import baseAddress_toAddress :: BaseAddress -> Address
foreign import baseAddress_fromAddress :: Address -> Nullable BaseAddress

instance IsCsl BaseAddress where
  className _ = "BaseAddress"

--------------------------------------------------------------------------------
-- Big int

foreign import data BigInt :: Type

foreign import bigInt_isZero :: BigInt -> Boolean
foreign import bigInt_asU64 :: BigInt -> Nullable BigNum
foreign import bigInt_asInt :: BigInt -> Nullable Int
foreign import bigInt_fromStr :: String -> Nullable BigInt
foreign import bigInt_toStr :: BigInt -> String
foreign import bigInt_mul :: BigInt -> BigInt -> BigInt
foreign import bigInt_one :: BigInt
foreign import bigInt_increment :: BigInt -> BigInt
foreign import bigInt_divCeil :: BigInt -> BigInt -> BigInt

instance IsCsl BigInt where
  className _ = "BigInt"

instance IsBytes BigInt
instance IsJson BigInt
instance EncodeAeson BigInt where
  encodeAeson = cslToAeson

instance DecodeAeson BigInt where
  decodeAeson = cslFromAeson

instance Show BigInt where
  show = showViaJson

--------------------------------------------------------------------------------
-- Big num

foreign import data BigNum :: Type

foreign import bigNum_fromStr :: String -> Nullable BigNum
foreign import bigNum_toStr :: BigNum -> String
foreign import bigNum_zero :: BigNum
foreign import bigNum_one :: BigNum
foreign import bigNum_isZero :: BigNum -> Boolean
foreign import bigNum_divFloor :: BigNum -> BigNum -> BigNum
foreign import bigNum_checkedMul :: BigNum -> BigNum -> Nullable BigNum
foreign import bigNum_checkedAdd :: BigNum -> BigNum -> Nullable BigNum
foreign import bigNum_checkedSub :: BigNum -> BigNum -> Nullable BigNum
foreign import bigNum_clampedSub :: BigNum -> BigNum -> BigNum
foreign import bigNum_compare :: BigNum -> BigNum -> Number
foreign import bigNum_lessThan :: BigNum -> BigNum -> Boolean
foreign import bigNum_maxValue :: BigNum
foreign import bigNum_max :: BigNum -> BigNum -> BigNum

instance IsCsl BigNum where
  className _ = "BigNum"

instance IsBytes BigNum
instance IsJson BigNum
instance EncodeAeson BigNum where
  encodeAeson = cslToAeson

instance DecodeAeson BigNum where
  decodeAeson = cslFromAeson

instance Show BigNum where
  show = showViaJson

--------------------------------------------------------------------------------
-- Bip32 private key

foreign import data Bip32PrivateKey :: Type

foreign import bip32PrivateKey_derive :: Bip32PrivateKey -> Number -> Bip32PrivateKey
foreign import bip32PrivateKey_from128Xprv :: ByteArray -> Bip32PrivateKey
foreign import bip32PrivateKey_to128Xprv :: Bip32PrivateKey -> ByteArray
foreign import bip32PrivateKey_generateEd25519Bip32 :: Bip32PrivateKey
foreign import bip32PrivateKey_toRawKey :: Bip32PrivateKey -> PrivateKey
foreign import bip32PrivateKey_toPublic :: Bip32PrivateKey -> Bip32PublicKey
foreign import bip32PrivateKey_asBytes :: Bip32PrivateKey -> ByteArray
foreign import bip32PrivateKey_fromBech32 :: String -> Nullable Bip32PrivateKey
foreign import bip32PrivateKey_toBech32 :: Bip32PrivateKey -> String
foreign import bip32PrivateKey_fromBip39Entropy :: ByteArray -> ByteArray -> Bip32PrivateKey
foreign import bip32PrivateKey_chaincode :: Bip32PrivateKey -> ByteArray

instance IsCsl Bip32PrivateKey where
  className _ = "Bip32PrivateKey"

--------------------------------------------------------------------------------
-- Bip32 public key

foreign import data Bip32PublicKey :: Type

foreign import bip32PublicKey_chaincode :: Bip32PublicKey -> ByteArray
foreign import bip32PublicKey_toBech32 :: Bip32PublicKey -> String
foreign import bip32PublicKey_fromBech32 :: String -> Nullable Bip32PublicKey
foreign import bip32PublicKey_asBytes :: Bip32PublicKey -> ByteArray
foreign import bip32PublicKey_toRawKey :: Bip32PublicKey -> PublicKey
foreign import bip32PublicKey_derive :: Bip32PublicKey -> Number -> Bip32PublicKey

instance IsCsl Bip32PublicKey where
  className _ = "Bip32PublicKey"

--------------------------------------------------------------------------------
-- Block hash

foreign import data BlockHash :: Type

foreign import blockHash_toBech32 :: BlockHash -> String -> String
foreign import blockHash_fromBech32 :: String -> Nullable BlockHash

instance IsCsl BlockHash where
  className _ = "BlockHash"

instance IsBytes BlockHash
instance EncodeAeson BlockHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson BlockHash where
  decodeAeson = cslFromAesonViaBytes

instance Show BlockHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Bootstrap witness

foreign import data BootstrapWitness :: Type

foreign import bootstrapWitness_vkey :: BootstrapWitness -> Vkey
foreign import bootstrapWitness_signature :: BootstrapWitness -> Ed25519Signature
foreign import bootstrapWitness_chainCode :: BootstrapWitness -> ByteArray
foreign import bootstrapWitness_attributes :: BootstrapWitness -> ByteArray
foreign import bootstrapWitness_new :: Vkey -> Ed25519Signature -> ByteArray -> ByteArray -> BootstrapWitness

instance IsCsl BootstrapWitness where
  className _ = "BootstrapWitness"

instance IsBytes BootstrapWitness
instance IsJson BootstrapWitness
instance EncodeAeson BootstrapWitness where
  encodeAeson = cslToAeson

instance DecodeAeson BootstrapWitness where
  decodeAeson = cslFromAeson

instance Show BootstrapWitness where
  show = showViaJson

--------------------------------------------------------------------------------
-- Bootstrap witnesses

foreign import data BootstrapWitnesses :: Type

foreign import bootstrapWitnesses_new :: Effect BootstrapWitnesses

instance IsCsl BootstrapWitnesses where
  className _ = "BootstrapWitnesses"

instance IsListContainer BootstrapWitnesses BootstrapWitness

--------------------------------------------------------------------------------
-- Byron address

foreign import data ByronAddress :: Type

foreign import byronAddress_toBase58 :: ByronAddress -> String
foreign import byronAddress_byronProtocolMagic :: ByronAddress -> Number
foreign import byronAddress_attributes :: ByronAddress -> ByteArray
foreign import byronAddress_networkId :: ByronAddress -> Number
foreign import byronAddress_fromBase58 :: String -> Nullable ByronAddress
foreign import byronAddress_icarusFromKey :: Bip32PublicKey -> Number -> ByronAddress
foreign import byronAddress_isValid :: String -> Boolean
foreign import byronAddress_toAddress :: ByronAddress -> Address
foreign import byronAddress_fromAddress :: Address -> Nullable ByronAddress

instance IsCsl ByronAddress where
  className _ = "ByronAddress"

instance IsBytes ByronAddress
instance EncodeAeson ByronAddress where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson ByronAddress where
  decodeAeson = cslFromAesonViaBytes

instance Show ByronAddress where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Certificate

foreign import data Certificate :: Type

foreign import certificate_newStakeRegistration :: StakeRegistration -> Certificate
foreign import certificate_newStakeDeregistration :: StakeDeregistration -> Certificate
foreign import certificate_newStakeDelegation :: StakeDelegation -> Certificate
foreign import certificate_newPoolRegistration :: PoolRegistration -> Certificate
foreign import certificate_newPoolRetirement :: PoolRetirement -> Certificate
foreign import certificate_newGenesisKeyDelegation :: GenesisKeyDelegation -> Certificate
foreign import certificate_newMoveInstantaneousRewardsCert :: MoveInstantaneousRewardsCert -> Certificate
foreign import certificate_newCommitteeHotAuth :: CommitteeHotAuth -> Certificate
foreign import certificate_newCommitteeColdResign :: CommitteeColdResign -> Certificate
foreign import certificate_newDrepDeregistration :: DrepDeregistration -> Certificate
foreign import certificate_newDrepRegistration :: DrepRegistration -> Certificate
foreign import certificate_newDrepUpdate :: DrepUpdate -> Certificate
foreign import certificate_newStakeAndVoteDelegation :: StakeAndVoteDelegation -> Certificate
foreign import certificate_newStakeRegistrationAndDelegation :: StakeRegistrationAndDelegation -> Certificate
foreign import certificate_newStakeVoteRegistrationAndDelegation :: StakeVoteRegistrationAndDelegation -> Certificate
foreign import certificate_newVoteDelegation :: VoteDelegation -> Certificate
foreign import certificate_newVoteRegistrationAndDelegation :: VoteRegistrationAndDelegation -> Certificate
foreign import certificate_kind :: Certificate -> CertificateKind
foreign import certificate_asStakeRegistration :: Certificate -> Nullable StakeRegistration
foreign import certificate_asStakeDeregistration :: Certificate -> Nullable StakeDeregistration
foreign import certificate_asStakeDelegation :: Certificate -> Nullable StakeDelegation
foreign import certificate_asPoolRegistration :: Certificate -> Nullable PoolRegistration
foreign import certificate_asPoolRetirement :: Certificate -> Nullable PoolRetirement
foreign import certificate_asGenesisKeyDelegation :: Certificate -> Nullable GenesisKeyDelegation
foreign import certificate_asMoveInstantaneousRewardsCert :: Certificate -> Nullable MoveInstantaneousRewardsCert
foreign import certificate_asCommitteeHotAuth :: Certificate -> Nullable CommitteeHotAuth
foreign import certificate_asCommitteeColdResign :: Certificate -> Nullable CommitteeColdResign
foreign import certificate_asDrepDeregistration :: Certificate -> Nullable DrepDeregistration
foreign import certificate_asDrepRegistration :: Certificate -> Nullable DrepRegistration
foreign import certificate_asDrepUpdate :: Certificate -> Nullable DrepUpdate
foreign import certificate_asStakeAndVoteDelegation :: Certificate -> Nullable StakeAndVoteDelegation
foreign import certificate_asStakeRegistrationAndDelegation :: Certificate -> Nullable StakeRegistrationAndDelegation
foreign import certificate_asStakeVoteRegistrationAndDelegation :: Certificate -> Nullable StakeVoteRegistrationAndDelegation
foreign import certificate_asVoteDelegation :: Certificate -> Nullable VoteDelegation
foreign import certificate_asVoteRegistrationAndDelegation :: Certificate -> Nullable VoteRegistrationAndDelegation
foreign import certificate_hasRequiredScriptWitness :: Certificate -> Boolean

instance IsCsl Certificate where
  className _ = "Certificate"

instance IsBytes Certificate
instance IsJson Certificate
instance EncodeAeson Certificate where
  encodeAeson = cslToAeson

instance DecodeAeson Certificate where
  decodeAeson = cslFromAeson

instance Show Certificate where
  show = showViaJson

--------------------------------------------------------------------------------
-- Certificates

foreign import data Certificates :: Type

foreign import certificates_new :: Effect Certificates

instance IsCsl Certificates where
  className _ = "Certificates"

instance IsBytes Certificates
instance IsJson Certificates
instance EncodeAeson Certificates where
  encodeAeson = cslToAeson

instance DecodeAeson Certificates where
  decodeAeson = cslFromAeson

instance Show Certificates where
  show = showViaJson

instance IsListContainer Certificates Certificate

--------------------------------------------------------------------------------
-- Change config

foreign import data ChangeConfig :: Type

foreign import changeConfig_new :: Address -> ChangeConfig
foreign import changeConfig_changeAddress :: ChangeConfig -> Address -> ChangeConfig
foreign import changeConfig_changePlutusData :: ChangeConfig -> OutputDatum -> ChangeConfig
foreign import changeConfig_changeScriptRef :: ChangeConfig -> ScriptRef -> ChangeConfig

instance IsCsl ChangeConfig where
  className _ = "ChangeConfig"

--------------------------------------------------------------------------------
-- Committee

foreign import data Committee :: Type

foreign import committee_new :: UnitInterval -> Effect Committee
foreign import committee_membersKeys :: Committee -> Credentials
foreign import committee_quorumThreshold :: Committee -> UnitInterval
foreign import committee_addMember :: Committee -> Credential -> Number -> Effect Unit
foreign import committee_getMemberEpoch :: Committee -> Credential -> Nullable Number

instance IsCsl Committee where
  className _ = "Committee"

instance IsBytes Committee
instance IsJson Committee
instance EncodeAeson Committee where
  encodeAeson = cslToAeson

instance DecodeAeson Committee where
  decodeAeson = cslFromAeson

instance Show Committee where
  show = showViaJson

--------------------------------------------------------------------------------
-- Committee cold resign

foreign import data CommitteeColdResign :: Type

foreign import committeeColdResign_committeeColdKey :: CommitteeColdResign -> Credential
foreign import committeeColdResign_anchor :: CommitteeColdResign -> Nullable Anchor
foreign import committeeColdResign_new :: Credential -> CommitteeColdResign
foreign import committeeColdResign_newWithAnchor :: Credential -> Anchor -> CommitteeColdResign
foreign import committeeColdResign_hasScriptCredentials :: CommitteeColdResign -> Boolean

instance IsCsl CommitteeColdResign where
  className _ = "CommitteeColdResign"

instance IsBytes CommitteeColdResign
instance IsJson CommitteeColdResign
instance EncodeAeson CommitteeColdResign where
  encodeAeson = cslToAeson

instance DecodeAeson CommitteeColdResign where
  decodeAeson = cslFromAeson

instance Show CommitteeColdResign where
  show = showViaJson

--------------------------------------------------------------------------------
-- Committee hot auth

foreign import data CommitteeHotAuth :: Type

foreign import committeeHotAuth_committeeColdKey :: CommitteeHotAuth -> Credential
foreign import committeeHotAuth_committeeHotKey :: CommitteeHotAuth -> Credential
foreign import committeeHotAuth_new :: Credential -> Credential -> CommitteeHotAuth
foreign import committeeHotAuth_hasScriptCredentials :: CommitteeHotAuth -> Boolean

instance IsCsl CommitteeHotAuth where
  className _ = "CommitteeHotAuth"

instance IsBytes CommitteeHotAuth
instance IsJson CommitteeHotAuth
instance EncodeAeson CommitteeHotAuth where
  encodeAeson = cslToAeson

instance DecodeAeson CommitteeHotAuth where
  decodeAeson = cslFromAeson

instance Show CommitteeHotAuth where
  show = showViaJson

--------------------------------------------------------------------------------
-- Constitution

foreign import data Constitution :: Type

foreign import constitution_anchor :: Constitution -> Anchor
foreign import constitution_scriptHash :: Constitution -> Nullable ScriptHash
foreign import constitution_new :: Anchor -> Constitution
foreign import constitution_newWithScriptHash :: Anchor -> ScriptHash -> Constitution

instance IsCsl Constitution where
  className _ = "Constitution"

instance IsBytes Constitution
instance IsJson Constitution
instance EncodeAeson Constitution where
  encodeAeson = cslToAeson

instance DecodeAeson Constitution where
  decodeAeson = cslFromAeson

instance Show Constitution where
  show = showViaJson

--------------------------------------------------------------------------------
-- Constr plutus data

foreign import data ConstrPlutusData :: Type

foreign import constrPlutusData_alternative :: ConstrPlutusData -> BigNum
foreign import constrPlutusData_data :: ConstrPlutusData -> PlutusList
foreign import constrPlutusData_new :: BigNum -> PlutusList -> ConstrPlutusData

instance IsCsl ConstrPlutusData where
  className _ = "ConstrPlutusData"

instance IsBytes ConstrPlutusData
instance EncodeAeson ConstrPlutusData where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson ConstrPlutusData where
  decodeAeson = cslFromAesonViaBytes

instance Show ConstrPlutusData where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Cost model

foreign import data CostModel :: Type

foreign import costModel_free :: CostModel -> Nullable Unit
foreign import costModel_toBytes :: CostModel -> ByteArray
foreign import costModel_fromBytes :: ByteArray -> Nullable CostModel
foreign import costModel_toHex :: CostModel -> String
foreign import costModel_fromHex :: String -> Nullable CostModel
foreign import costModel_toJson :: CostModel -> String
foreign import costModel_fromJson :: String -> Nullable CostModel
foreign import costModel_new :: Effect CostModel
foreign import costModel_set :: CostModel -> Number -> Int -> Effect Int
foreign import costModel_get :: CostModel -> Number -> Effect Int
foreign import costModel_len :: CostModel -> Effect Number

instance IsCsl CostModel where
  className _ = "CostModel"

instance IsBytes CostModel
instance IsJson CostModel
instance EncodeAeson CostModel where
  encodeAeson = cslToAeson

instance DecodeAeson CostModel where
  decodeAeson = cslFromAeson

instance Show CostModel where
  show = showViaJson

--------------------------------------------------------------------------------
-- Costmdls

foreign import data Costmdls :: Type

foreign import costmdls_new :: Effect Costmdls
foreign import costmdls_retainLanguageVersions :: Costmdls -> Languages -> Costmdls

instance IsCsl Costmdls where
  className _ = "Costmdls"

instance IsBytes Costmdls
instance IsJson Costmdls
instance EncodeAeson Costmdls where
  encodeAeson = cslToAeson

instance DecodeAeson Costmdls where
  decodeAeson = cslFromAeson

instance Show Costmdls where
  show = showViaJson

instance IsMapContainer Costmdls Language CostModel

--------------------------------------------------------------------------------
-- Credential

foreign import data Credential :: Type

foreign import credential_fromKeyhash :: Ed25519KeyHash -> Credential
foreign import credential_fromScripthash :: ScriptHash -> Credential
foreign import credential_toKeyhash :: Credential -> Nullable Ed25519KeyHash
foreign import credential_toScripthash :: Credential -> Nullable ScriptHash
foreign import credential_kind :: Credential -> CredKind
foreign import credential_hasScriptHash :: Credential -> Boolean

instance IsCsl Credential where
  className _ = "Credential"

instance IsBytes Credential
instance IsJson Credential
instance EncodeAeson Credential where
  encodeAeson = cslToAeson

instance DecodeAeson Credential where
  decodeAeson = cslFromAeson

instance Show Credential where
  show = showViaJson

--------------------------------------------------------------------------------
-- Credentials

foreign import data Credentials :: Type

foreign import credentials_new :: Credentials

instance IsCsl Credentials where
  className _ = "Credentials"

instance IsBytes Credentials
instance IsJson Credentials
instance EncodeAeson Credentials where
  encodeAeson = cslToAeson

instance DecodeAeson Credentials where
  decodeAeson = cslFromAeson

instance Show Credentials where
  show = showViaJson

instance IsListContainer Credentials Credential

--------------------------------------------------------------------------------
-- DNSRecord aor aaaa

foreign import data DNSRecordAorAAAA :: Type

foreign import dnsRecordAorAAAA_new :: String -> DNSRecordAorAAAA
foreign import dnsRecordAorAAAA_record :: DNSRecordAorAAAA -> String

instance IsCsl DNSRecordAorAAAA where
  className _ = "DNSRecordAorAAAA"

instance IsBytes DNSRecordAorAAAA
instance IsJson DNSRecordAorAAAA
instance EncodeAeson DNSRecordAorAAAA where
  encodeAeson = cslToAeson

instance DecodeAeson DNSRecordAorAAAA where
  decodeAeson = cslFromAeson

instance Show DNSRecordAorAAAA where
  show = showViaJson

--------------------------------------------------------------------------------
-- DNSRecord srv

foreign import data DNSRecordSRV :: Type

foreign import dnsRecordSRV_new :: String -> DNSRecordSRV
foreign import dnsRecordSRV_record :: DNSRecordSRV -> String

instance IsCsl DNSRecordSRV where
  className _ = "DNSRecordSRV"

instance IsBytes DNSRecordSRV
instance IsJson DNSRecordSRV
instance EncodeAeson DNSRecordSRV where
  encodeAeson = cslToAeson

instance DecodeAeson DNSRecordSRV where
  decodeAeson = cslFromAeson

instance Show DNSRecordSRV where
  show = showViaJson

--------------------------------------------------------------------------------
-- DRep

foreign import data DRep :: Type

foreign import dRep_newKeyHash :: Ed25519KeyHash -> DRep
foreign import dRep_newScriptHash :: ScriptHash -> DRep
foreign import dRep_newAlwaysAbstain :: DRep
foreign import dRep_newAlwaysNoConfidence :: DRep
foreign import dRep_kind :: DRep -> DRepKind
foreign import dRep_toKeyHash :: DRep -> Nullable Ed25519KeyHash
foreign import dRep_toScriptHash :: DRep -> Nullable ScriptHash

instance IsCsl DRep where
  className _ = "DRep"

instance IsBytes DRep
instance IsJson DRep
instance EncodeAeson DRep where
  encodeAeson = cslToAeson

instance DecodeAeson DRep where
  decodeAeson = cslFromAeson

instance Show DRep where
  show = showViaJson

--------------------------------------------------------------------------------
-- Data cost

foreign import data DataCost :: Type

foreign import dataCost_newCoinsPerByte :: BigNum -> DataCost
foreign import dataCost_coinsPerByte :: DataCost -> BigNum

instance IsCsl DataCost where
  className _ = "DataCost"

--------------------------------------------------------------------------------
-- Data hash

foreign import data DataHash :: Type

foreign import dataHash_toBech32 :: DataHash -> String -> String
foreign import dataHash_fromBech32 :: String -> Nullable DataHash

instance IsCsl DataHash where
  className _ = "DataHash"

instance IsBytes DataHash
instance EncodeAeson DataHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson DataHash where
  decodeAeson = cslFromAesonViaBytes

instance Show DataHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Datum source

foreign import data DatumSource :: Type

foreign import datumSource_new :: PlutusData -> DatumSource
foreign import datumSource_newRefInput :: TransactionInput -> DatumSource

instance IsCsl DatumSource where
  className _ = "DatumSource"

--------------------------------------------------------------------------------
-- Drep deregistration

foreign import data DrepDeregistration :: Type

foreign import drepDeregistration_votingCredential :: DrepDeregistration -> Credential
foreign import drepDeregistration_coin :: DrepDeregistration -> BigNum
foreign import drepDeregistration_new :: Credential -> BigNum -> DrepDeregistration
foreign import drepDeregistration_hasScriptCredentials :: DrepDeregistration -> Boolean

instance IsCsl DrepDeregistration where
  className _ = "DrepDeregistration"

instance IsBytes DrepDeregistration
instance IsJson DrepDeregistration
instance EncodeAeson DrepDeregistration where
  encodeAeson = cslToAeson

instance DecodeAeson DrepDeregistration where
  decodeAeson = cslFromAeson

instance Show DrepDeregistration where
  show = showViaJson

--------------------------------------------------------------------------------
-- Drep registration

foreign import data DrepRegistration :: Type

foreign import drepRegistration_votingCredential :: DrepRegistration -> Credential
foreign import drepRegistration_coin :: DrepRegistration -> BigNum
foreign import drepRegistration_anchor :: DrepRegistration -> Nullable Anchor
foreign import drepRegistration_new :: Credential -> BigNum -> DrepRegistration
foreign import drepRegistration_newWithAnchor :: Credential -> BigNum -> Anchor -> DrepRegistration
foreign import drepRegistration_hasScriptCredentials :: DrepRegistration -> Boolean

instance IsCsl DrepRegistration where
  className _ = "DrepRegistration"

instance IsBytes DrepRegistration
instance IsJson DrepRegistration
instance EncodeAeson DrepRegistration where
  encodeAeson = cslToAeson

instance DecodeAeson DrepRegistration where
  decodeAeson = cslFromAeson

instance Show DrepRegistration where
  show = showViaJson

--------------------------------------------------------------------------------
-- Drep update

foreign import data DrepUpdate :: Type

foreign import drepUpdate_votingCredential :: DrepUpdate -> Credential
foreign import drepUpdate_anchor :: DrepUpdate -> Nullable Anchor
foreign import drepUpdate_new :: Credential -> DrepUpdate
foreign import drepUpdate_newWithAnchor :: Credential -> Anchor -> DrepUpdate
foreign import drepUpdate_hasScriptCredentials :: DrepUpdate -> Boolean

instance IsCsl DrepUpdate where
  className _ = "DrepUpdate"

instance IsBytes DrepUpdate
instance IsJson DrepUpdate
instance EncodeAeson DrepUpdate where
  encodeAeson = cslToAeson

instance DecodeAeson DrepUpdate where
  decodeAeson = cslFromAeson

instance Show DrepUpdate where
  show = showViaJson

--------------------------------------------------------------------------------
-- Drep voting thresholds

foreign import data DrepVotingThresholds :: Type

foreign import drepVotingThresholds_new :: UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> DrepVotingThresholds
foreign import drepVotingThresholds_newDefault :: DrepVotingThresholds
foreign import drepVotingThresholds_setMotionNoConfidence :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setCommitteeNormal :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setCommitteeNoConfidence :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setUpdateConstitution :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setHardForkInitiation :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setPpNetworkGroup :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setPpEconomicGroup :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setPpTechnicalGroup :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setPpGovernanceGroup :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_setTreasuryWithdrawal :: DrepVotingThresholds -> UnitInterval -> Effect Unit
foreign import drepVotingThresholds_motionNoConfidence :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_committeeNormal :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_committeeNoConfidence :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_updateConstitution :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_hardForkInitiation :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_ppNetworkGroup :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_ppEconomicGroup :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_ppTechnicalGroup :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_ppGovernanceGroup :: DrepVotingThresholds -> UnitInterval
foreign import drepVotingThresholds_treasuryWithdrawal :: DrepVotingThresholds -> UnitInterval

instance IsCsl DrepVotingThresholds where
  className _ = "DrepVotingThresholds"

instance IsBytes DrepVotingThresholds
instance IsJson DrepVotingThresholds
instance EncodeAeson DrepVotingThresholds where
  encodeAeson = cslToAeson

instance DecodeAeson DrepVotingThresholds where
  decodeAeson = cslFromAeson

instance Show DrepVotingThresholds where
  show = showViaJson

--------------------------------------------------------------------------------
-- Ed25519 key hash

foreign import data Ed25519KeyHash :: Type

foreign import ed25519KeyHash_toBech32 :: Ed25519KeyHash -> String -> String
foreign import ed25519KeyHash_fromBech32 :: String -> Nullable Ed25519KeyHash

instance IsCsl Ed25519KeyHash where
  className _ = "Ed25519KeyHash"

instance IsBytes Ed25519KeyHash
instance EncodeAeson Ed25519KeyHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson Ed25519KeyHash where
  decodeAeson = cslFromAesonViaBytes

instance Show Ed25519KeyHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Ed25519 key hashes

foreign import data Ed25519KeyHashes :: Type

foreign import ed25519KeyHashes_new :: Ed25519KeyHashes
foreign import ed25519KeyHashes_contains :: Ed25519KeyHashes -> Ed25519KeyHash -> Boolean
foreign import ed25519KeyHashes_toOption :: Ed25519KeyHashes -> Nullable Ed25519KeyHashes

instance IsCsl Ed25519KeyHashes where
  className _ = "Ed25519KeyHashes"

instance IsBytes Ed25519KeyHashes
instance IsJson Ed25519KeyHashes
instance EncodeAeson Ed25519KeyHashes where
  encodeAeson = cslToAeson

instance DecodeAeson Ed25519KeyHashes where
  decodeAeson = cslFromAeson

instance Show Ed25519KeyHashes where
  show = showViaJson

instance IsListContainer Ed25519KeyHashes Ed25519KeyHash

--------------------------------------------------------------------------------
-- Ed25519 signature

foreign import data Ed25519Signature :: Type

foreign import ed25519Signature_toBech32 :: Ed25519Signature -> String
foreign import ed25519Signature_fromBech32 :: String -> Nullable Ed25519Signature

instance IsCsl Ed25519Signature where
  className _ = "Ed25519Signature"

instance IsBytes Ed25519Signature
instance EncodeAeson Ed25519Signature where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson Ed25519Signature where
  decodeAeson = cslFromAesonViaBytes

instance Show Ed25519Signature where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Enterprise address

foreign import data EnterpriseAddress :: Type

foreign import enterpriseAddress_new :: Number -> Credential -> EnterpriseAddress
foreign import enterpriseAddress_paymentCred :: EnterpriseAddress -> Credential
foreign import enterpriseAddress_toAddress :: EnterpriseAddress -> Address
foreign import enterpriseAddress_fromAddress :: Address -> Nullable EnterpriseAddress

instance IsCsl EnterpriseAddress where
  className _ = "EnterpriseAddress"

--------------------------------------------------------------------------------
-- Ex unit prices

foreign import data ExUnitPrices :: Type

foreign import exUnitPrices_memPrice :: ExUnitPrices -> UnitInterval
foreign import exUnitPrices_stepPrice :: ExUnitPrices -> UnitInterval
foreign import exUnitPrices_new :: UnitInterval -> UnitInterval -> ExUnitPrices

instance IsCsl ExUnitPrices where
  className _ = "ExUnitPrices"

instance IsBytes ExUnitPrices
instance IsJson ExUnitPrices
instance EncodeAeson ExUnitPrices where
  encodeAeson = cslToAeson

instance DecodeAeson ExUnitPrices where
  decodeAeson = cslFromAeson

instance Show ExUnitPrices where
  show = showViaJson

--------------------------------------------------------------------------------
-- Ex units

foreign import data ExUnits :: Type

foreign import exUnits_mem :: ExUnits -> BigNum
foreign import exUnits_steps :: ExUnits -> BigNum
foreign import exUnits_new :: BigNum -> BigNum -> ExUnits

instance IsCsl ExUnits where
  className _ = "ExUnits"

instance IsBytes ExUnits
instance IsJson ExUnits
instance EncodeAeson ExUnits where
  encodeAeson = cslToAeson

instance DecodeAeson ExUnits where
  decodeAeson = cslFromAeson

instance Show ExUnits where
  show = showViaJson

--------------------------------------------------------------------------------
-- General transaction metadata

foreign import data GeneralTransactionMetadata :: Type

foreign import generalTransactionMetadata_new :: Effect GeneralTransactionMetadata

instance IsCsl GeneralTransactionMetadata where
  className _ = "GeneralTransactionMetadata"

instance IsBytes GeneralTransactionMetadata
instance IsJson GeneralTransactionMetadata
instance EncodeAeson GeneralTransactionMetadata where
  encodeAeson = cslToAeson

instance DecodeAeson GeneralTransactionMetadata where
  decodeAeson = cslFromAeson

instance Show GeneralTransactionMetadata where
  show = showViaJson

instance IsMapContainer GeneralTransactionMetadata BigNum TransactionMetadatum

--------------------------------------------------------------------------------
-- Genesis delegate hash

foreign import data GenesisDelegateHash :: Type

foreign import genesisDelegateHash_toBech32 :: GenesisDelegateHash -> String -> String
foreign import genesisDelegateHash_fromBech32 :: String -> Nullable GenesisDelegateHash

instance IsCsl GenesisDelegateHash where
  className _ = "GenesisDelegateHash"

instance IsBytes GenesisDelegateHash
instance EncodeAeson GenesisDelegateHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson GenesisDelegateHash where
  decodeAeson = cslFromAesonViaBytes

instance Show GenesisDelegateHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Genesis hash

foreign import data GenesisHash :: Type

foreign import genesisHash_toBech32 :: GenesisHash -> String -> String
foreign import genesisHash_fromBech32 :: String -> Nullable GenesisHash

instance IsCsl GenesisHash where
  className _ = "GenesisHash"

instance IsBytes GenesisHash
instance EncodeAeson GenesisHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson GenesisHash where
  decodeAeson = cslFromAesonViaBytes

instance Show GenesisHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Genesis hashes

foreign import data GenesisHashes :: Type

foreign import genesisHashes_new :: Effect GenesisHashes

instance IsCsl GenesisHashes where
  className _ = "GenesisHashes"

instance IsBytes GenesisHashes
instance IsJson GenesisHashes
instance EncodeAeson GenesisHashes where
  encodeAeson = cslToAeson

instance DecodeAeson GenesisHashes where
  decodeAeson = cslFromAeson

instance Show GenesisHashes where
  show = showViaJson

instance IsListContainer GenesisHashes GenesisHash

--------------------------------------------------------------------------------
-- Genesis key delegation

foreign import data GenesisKeyDelegation :: Type

foreign import genesisKeyDelegation_genesishash :: GenesisKeyDelegation -> GenesisHash
foreign import genesisKeyDelegation_genesisDelegateHash :: GenesisKeyDelegation -> GenesisDelegateHash
foreign import genesisKeyDelegation_vrfKeyhash :: GenesisKeyDelegation -> VRFKeyHash
foreign import genesisKeyDelegation_new :: GenesisHash -> GenesisDelegateHash -> VRFKeyHash -> GenesisKeyDelegation

instance IsCsl GenesisKeyDelegation where
  className _ = "GenesisKeyDelegation"

instance IsBytes GenesisKeyDelegation
instance IsJson GenesisKeyDelegation
instance EncodeAeson GenesisKeyDelegation where
  encodeAeson = cslToAeson

instance DecodeAeson GenesisKeyDelegation where
  decodeAeson = cslFromAeson

instance Show GenesisKeyDelegation where
  show = showViaJson

--------------------------------------------------------------------------------
-- Governance action

foreign import data GovernanceAction :: Type

foreign import governanceAction_newParameterChangeAction :: ParameterChangeAction -> GovernanceAction
foreign import governanceAction_newHardForkInitiationAction :: HardForkInitiationAction -> GovernanceAction
foreign import governanceAction_newTreasuryWithdrawalsAction :: TreasuryWithdrawalsAction -> GovernanceAction
foreign import governanceAction_newNoConfidenceAction :: NoConfidenceAction -> GovernanceAction
foreign import governanceAction_newNewCommitteeAction :: UpdateCommitteeAction -> GovernanceAction
foreign import governanceAction_newNewConstitutionAction :: NewConstitutionAction -> GovernanceAction
foreign import governanceAction_newInfoAction :: InfoAction -> GovernanceAction
foreign import governanceAction_kind :: GovernanceAction -> GovernanceActionKind
foreign import governanceAction_asParameterChangeAction :: GovernanceAction -> Nullable ParameterChangeAction
foreign import governanceAction_asHardForkInitiationAction :: GovernanceAction -> Nullable HardForkInitiationAction
foreign import governanceAction_asTreasuryWithdrawalsAction :: GovernanceAction -> Nullable TreasuryWithdrawalsAction
foreign import governanceAction_asNoConfidenceAction :: GovernanceAction -> Nullable NoConfidenceAction
foreign import governanceAction_asNewCommitteeAction :: GovernanceAction -> Nullable UpdateCommitteeAction
foreign import governanceAction_asNewConstitutionAction :: GovernanceAction -> Nullable NewConstitutionAction
foreign import governanceAction_asInfoAction :: GovernanceAction -> Nullable InfoAction

instance IsCsl GovernanceAction where
  className _ = "GovernanceAction"

instance IsBytes GovernanceAction
instance IsJson GovernanceAction
instance EncodeAeson GovernanceAction where
  encodeAeson = cslToAeson

instance DecodeAeson GovernanceAction where
  decodeAeson = cslFromAeson

instance Show GovernanceAction where
  show = showViaJson

--------------------------------------------------------------------------------
-- Governance action id

foreign import data GovernanceActionId :: Type

foreign import governanceActionId_transactionId :: GovernanceActionId -> TransactionHash
foreign import governanceActionId_index :: GovernanceActionId -> Number
foreign import governanceActionId_new :: TransactionHash -> Number -> GovernanceActionId

instance IsCsl GovernanceActionId where
  className _ = "GovernanceActionId"

instance IsBytes GovernanceActionId
instance IsJson GovernanceActionId
instance EncodeAeson GovernanceActionId where
  encodeAeson = cslToAeson

instance DecodeAeson GovernanceActionId where
  decodeAeson = cslFromAeson

instance Show GovernanceActionId where
  show = showViaJson

--------------------------------------------------------------------------------
-- Governance action ids

foreign import data GovernanceActionIds :: Type

foreign import governanceActionIds_new :: GovernanceActionIds

instance IsCsl GovernanceActionIds where
  className _ = "GovernanceActionIds"

instance IsJson GovernanceActionIds
instance EncodeAeson GovernanceActionIds where
  encodeAeson = cslToAeson

instance DecodeAeson GovernanceActionIds where
  decodeAeson = cslFromAeson

instance Show GovernanceActionIds where
  show = showViaJson

instance IsListContainer GovernanceActionIds GovernanceActionId

--------------------------------------------------------------------------------
-- Hard fork initiation action

foreign import data HardForkInitiationAction :: Type

foreign import hardForkInitiationAction_govActionId :: HardForkInitiationAction -> Nullable GovernanceActionId
foreign import hardForkInitiationAction_protocolVersion :: HardForkInitiationAction -> ProtocolVersion
foreign import hardForkInitiationAction_new :: ProtocolVersion -> HardForkInitiationAction
foreign import hardForkInitiationAction_newWithActionId :: GovernanceActionId -> ProtocolVersion -> HardForkInitiationAction

instance IsCsl HardForkInitiationAction where
  className _ = "HardForkInitiationAction"

instance IsBytes HardForkInitiationAction
instance IsJson HardForkInitiationAction
instance EncodeAeson HardForkInitiationAction where
  encodeAeson = cslToAeson

instance DecodeAeson HardForkInitiationAction where
  decodeAeson = cslFromAeson

instance Show HardForkInitiationAction where
  show = showViaJson

--------------------------------------------------------------------------------
-- Info action

foreign import data InfoAction :: Type

foreign import infoAction_new :: InfoAction

instance IsCsl InfoAction where
  className _ = "InfoAction"

--------------------------------------------------------------------------------
-- Int

foreign import data Int :: Type

foreign import int_new :: BigNum -> Int
foreign import int_newNegative :: BigNum -> Int
foreign import int_newI32 :: Number -> Int
foreign import int_isPositive :: Int -> Boolean
foreign import int_asPositive :: Int -> Nullable BigNum
foreign import int_asNegative :: Int -> Nullable BigNum
foreign import int_asI32 :: Int -> Nullable Number
foreign import int_asI32OrNothing :: Int -> Nullable Number
foreign import int_asI32OrFail :: Int -> Number
foreign import int_toStr :: Int -> String
foreign import int_fromStr :: String -> Nullable Int

instance IsCsl Int where
  className _ = "Int"

instance IsBytes Int
instance IsJson Int
instance EncodeAeson Int where
  encodeAeson = cslToAeson

instance DecodeAeson Int where
  decodeAeson = cslFromAeson

instance Show Int where
  show = showViaJson

--------------------------------------------------------------------------------
-- Ipv4

foreign import data Ipv4 :: Type

foreign import ipv4_new :: ByteArray -> Ipv4
foreign import ipv4_ip :: Ipv4 -> ByteArray

instance IsCsl Ipv4 where
  className _ = "Ipv4"

instance IsBytes Ipv4
instance IsJson Ipv4
instance EncodeAeson Ipv4 where
  encodeAeson = cslToAeson

instance DecodeAeson Ipv4 where
  decodeAeson = cslFromAeson

instance Show Ipv4 where
  show = showViaJson

--------------------------------------------------------------------------------
-- Ipv6

foreign import data Ipv6 :: Type

foreign import ipv6_new :: ByteArray -> Ipv6
foreign import ipv6_ip :: Ipv6 -> ByteArray

instance IsCsl Ipv6 where
  className _ = "Ipv6"

instance IsBytes Ipv6
instance IsJson Ipv6
instance EncodeAeson Ipv6 where
  encodeAeson = cslToAeson

instance DecodeAeson Ipv6 where
  decodeAeson = cslFromAeson

instance Show Ipv6 where
  show = showViaJson

--------------------------------------------------------------------------------
-- KESSignature

foreign import data KESSignature :: Type

instance IsCsl KESSignature where
  className _ = "KESSignature"

instance IsBytes KESSignature
instance EncodeAeson KESSignature where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson KESSignature where
  decodeAeson = cslFromAesonViaBytes

instance Show KESSignature where
  show = showViaBytes

--------------------------------------------------------------------------------
-- KESVKey

foreign import data KESVKey :: Type

foreign import kesvKey_toBech32 :: KESVKey -> String -> String
foreign import kesvKey_fromBech32 :: String -> Nullable KESVKey

instance IsCsl KESVKey where
  className _ = "KESVKey"

instance IsBytes KESVKey
instance EncodeAeson KESVKey where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson KESVKey where
  decodeAeson = cslFromAesonViaBytes

instance Show KESVKey where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Language

foreign import data Language :: Type

foreign import language_newPlutusV1 :: Language
foreign import language_newPlutusV2 :: Language
foreign import language_newPlutusV3 :: Language
foreign import language_kind :: Language -> LanguageKind

instance IsCsl Language where
  className _ = "Language"

instance IsBytes Language
instance IsJson Language
instance EncodeAeson Language where
  encodeAeson = cslToAeson

instance DecodeAeson Language where
  decodeAeson = cslFromAeson

instance Show Language where
  show = showViaJson

--------------------------------------------------------------------------------
-- Languages

foreign import data Languages :: Type

foreign import languages_new :: Effect Languages
foreign import languages_list :: Languages

instance IsCsl Languages where
  className _ = "Languages"

instance IsListContainer Languages Language

--------------------------------------------------------------------------------
-- Legacy daedalus private key

foreign import data LegacyDaedalusPrivateKey :: Type

foreign import legacyDaedalusPrivateKey_asBytes :: LegacyDaedalusPrivateKey -> ByteArray
foreign import legacyDaedalusPrivateKey_chaincode :: LegacyDaedalusPrivateKey -> ByteArray

instance IsCsl LegacyDaedalusPrivateKey where
  className _ = "LegacyDaedalusPrivateKey"

--------------------------------------------------------------------------------
-- Linear fee

foreign import data LinearFee :: Type

foreign import linearFee_constant :: LinearFee -> BigNum
foreign import linearFee_coefficient :: LinearFee -> BigNum
foreign import linearFee_new :: BigNum -> BigNum -> LinearFee

instance IsCsl LinearFee where
  className _ = "LinearFee"

--------------------------------------------------------------------------------
-- MIRTo stake credentials

foreign import data MIRToStakeCredentials :: Type

foreign import mirToStakeCredentials_new :: Effect MIRToStakeCredentials

instance IsCsl MIRToStakeCredentials where
  className _ = "MIRToStakeCredentials"

instance IsBytes MIRToStakeCredentials
instance IsJson MIRToStakeCredentials
instance EncodeAeson MIRToStakeCredentials where
  encodeAeson = cslToAeson

instance DecodeAeson MIRToStakeCredentials where
  decodeAeson = cslFromAeson

instance Show MIRToStakeCredentials where
  show = showViaJson

instance IsMapContainer MIRToStakeCredentials Credential Int

--------------------------------------------------------------------------------
-- Malformed address

foreign import data MalformedAddress :: Type

foreign import malformedAddress_originalBytes :: MalformedAddress -> ByteArray
foreign import malformedAddress_toAddress :: MalformedAddress -> Address
foreign import malformedAddress_fromAddress :: Address -> Nullable MalformedAddress

instance IsCsl MalformedAddress where
  className _ = "MalformedAddress"

--------------------------------------------------------------------------------
-- Metadata list

foreign import data MetadataList :: Type

foreign import metadataList_new :: Effect MetadataList

instance IsCsl MetadataList where
  className _ = "MetadataList"

instance IsBytes MetadataList
instance EncodeAeson MetadataList where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson MetadataList where
  decodeAeson = cslFromAesonViaBytes

instance Show MetadataList where
  show = showViaBytes

instance IsListContainer MetadataList TransactionMetadatum

--------------------------------------------------------------------------------
-- Metadata map

foreign import data MetadataMap :: Type

foreign import metadataMap_new :: Effect MetadataMap
foreign import metadataMap_insertStr :: MetadataMap -> String -> TransactionMetadatum -> Effect ((Nullable TransactionMetadatum))
foreign import metadataMap_insertI32 :: MetadataMap -> Number -> TransactionMetadatum -> Effect ((Nullable TransactionMetadatum))
foreign import metadataMap_getStr :: MetadataMap -> String -> Effect TransactionMetadatum
foreign import metadataMap_getI32 :: MetadataMap -> Number -> Effect TransactionMetadatum
foreign import metadataMap_has :: MetadataMap -> TransactionMetadatum -> Effect Boolean

instance IsCsl MetadataMap where
  className _ = "MetadataMap"

instance IsBytes MetadataMap
instance EncodeAeson MetadataMap where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson MetadataMap where
  decodeAeson = cslFromAesonViaBytes

instance Show MetadataMap where
  show = showViaBytes

instance IsMapContainer MetadataMap TransactionMetadatum TransactionMetadatum

--------------------------------------------------------------------------------
-- Mint

foreign import data Mint :: Type

foreign import mint_new :: Effect Mint
foreign import mint_newFromEntry :: ScriptHash -> MintAssets -> Effect Mint
foreign import mint_asPositiveMultiasset :: Mint -> Effect MultiAsset
foreign import mint_asNegativeMultiasset :: Mint -> Effect MultiAsset

instance IsCsl Mint where
  className _ = "Mint"

instance IsBytes Mint
instance IsJson Mint
instance EncodeAeson Mint where
  encodeAeson = cslToAeson

instance DecodeAeson Mint where
  decodeAeson = cslFromAeson

instance Show Mint where
  show = showViaJson

instance IsMultiMapContainer Mint ScriptHash MintAssets

--------------------------------------------------------------------------------
-- Mint assets

foreign import data MintAssets :: Type

foreign import mintAssets_new :: Effect MintAssets
foreign import mintAssets_newFromEntry :: AssetName -> Int -> MintAssets

instance IsCsl MintAssets where
  className _ = "MintAssets"

instance IsMapContainer MintAssets AssetName Int

--------------------------------------------------------------------------------
-- Mint witness

foreign import data MintWitness :: Type

foreign import mintWitness_newNativeScript :: NativeScriptSource -> MintWitness
foreign import mintWitness_newPlutusScript :: PlutusScriptSource -> Redeemer -> MintWitness

instance IsCsl MintWitness where
  className _ = "MintWitness"

--------------------------------------------------------------------------------
-- Mints assets

foreign import data MintsAssets :: Type

foreign import mintsAssets_new :: MintsAssets

instance IsCsl MintsAssets where
  className _ = "MintsAssets"

instance IsJson MintsAssets
instance EncodeAeson MintsAssets where
  encodeAeson = cslToAeson

instance DecodeAeson MintsAssets where
  decodeAeson = cslFromAeson

instance Show MintsAssets where
  show = showViaJson

instance IsListContainer MintsAssets MintAssets

--------------------------------------------------------------------------------
-- Move instantaneous reward

foreign import data MoveInstantaneousReward :: Type

foreign import moveInstantaneousReward_newToOtherPot :: MIRPot -> BigNum -> MoveInstantaneousReward
foreign import moveInstantaneousReward_newToStakeCreds :: MIRPot -> MIRToStakeCredentials -> MoveInstantaneousReward
foreign import moveInstantaneousReward_pot :: MoveInstantaneousReward -> MIRPot
foreign import moveInstantaneousReward_kind :: MoveInstantaneousReward -> MIRKind
foreign import moveInstantaneousReward_asToOtherPot :: MoveInstantaneousReward -> Nullable BigNum
foreign import moveInstantaneousReward_asToStakeCreds :: MoveInstantaneousReward -> Nullable MIRToStakeCredentials

instance IsCsl MoveInstantaneousReward where
  className _ = "MoveInstantaneousReward"

instance IsBytes MoveInstantaneousReward
instance IsJson MoveInstantaneousReward
instance EncodeAeson MoveInstantaneousReward where
  encodeAeson = cslToAeson

instance DecodeAeson MoveInstantaneousReward where
  decodeAeson = cslFromAeson

instance Show MoveInstantaneousReward where
  show = showViaJson

--------------------------------------------------------------------------------
-- Move instantaneous rewards cert

foreign import data MoveInstantaneousRewardsCert :: Type

foreign import moveInstantaneousRewardsCert_moveInstantaneousReward :: MoveInstantaneousRewardsCert -> MoveInstantaneousReward
foreign import moveInstantaneousRewardsCert_new :: MoveInstantaneousReward -> MoveInstantaneousRewardsCert

instance IsCsl MoveInstantaneousRewardsCert where
  className _ = "MoveInstantaneousRewardsCert"

instance IsBytes MoveInstantaneousRewardsCert
instance IsJson MoveInstantaneousRewardsCert
instance EncodeAeson MoveInstantaneousRewardsCert where
  encodeAeson = cslToAeson

instance DecodeAeson MoveInstantaneousRewardsCert where
  decodeAeson = cslFromAeson

instance Show MoveInstantaneousRewardsCert where
  show = showViaJson

--------------------------------------------------------------------------------
-- Multi asset

foreign import data MultiAsset :: Type

foreign import multiAsset_new :: Effect MultiAsset
foreign import multiAsset_setAsset :: MultiAsset -> ScriptHash -> AssetName -> BigNum -> Effect ((Nullable BigNum))
foreign import multiAsset_getAsset :: MultiAsset -> ScriptHash -> AssetName -> Effect BigNum
foreign import multiAsset_sub :: MultiAsset -> MultiAsset -> Effect MultiAsset

instance IsCsl MultiAsset where
  className _ = "MultiAsset"

instance IsBytes MultiAsset
instance IsJson MultiAsset
instance EncodeAeson MultiAsset where
  encodeAeson = cslToAeson

instance DecodeAeson MultiAsset where
  decodeAeson = cslFromAeson

instance Show MultiAsset where
  show = showViaJson

instance IsMapContainer MultiAsset ScriptHash Assets

--------------------------------------------------------------------------------
-- Multi host name

foreign import data MultiHostName :: Type

foreign import multiHostName_dnsName :: MultiHostName -> DNSRecordSRV
foreign import multiHostName_new :: DNSRecordSRV -> MultiHostName

instance IsCsl MultiHostName where
  className _ = "MultiHostName"

instance IsBytes MultiHostName
instance IsJson MultiHostName
instance EncodeAeson MultiHostName where
  encodeAeson = cslToAeson

instance DecodeAeson MultiHostName where
  decodeAeson = cslFromAeson

instance Show MultiHostName where
  show = showViaJson

--------------------------------------------------------------------------------
-- Native script

foreign import data NativeScript :: Type

foreign import nativeScript_hash :: NativeScript -> ScriptHash
foreign import nativeScript_newScriptPubkey :: ScriptPubkey -> NativeScript
foreign import nativeScript_newScriptAll :: ScriptAll -> NativeScript
foreign import nativeScript_newScriptAny :: ScriptAny -> NativeScript
foreign import nativeScript_newScriptNOfK :: ScriptNOfK -> NativeScript
foreign import nativeScript_newTimelockStart :: TimelockStart -> NativeScript
foreign import nativeScript_newTimelockExpiry :: TimelockExpiry -> NativeScript
foreign import nativeScript_kind :: NativeScript -> NativeScriptKind
foreign import nativeScript_asScriptPubkey :: NativeScript -> Nullable ScriptPubkey
foreign import nativeScript_asScriptAll :: NativeScript -> Nullable ScriptAll
foreign import nativeScript_asScriptAny :: NativeScript -> Nullable ScriptAny
foreign import nativeScript_asScriptNOfK :: NativeScript -> Nullable ScriptNOfK
foreign import nativeScript_asTimelockStart :: NativeScript -> Nullable TimelockStart
foreign import nativeScript_asTimelockExpiry :: NativeScript -> Nullable TimelockExpiry
foreign import nativeScript_getRequiredSigners :: NativeScript -> Ed25519KeyHashes

instance IsCsl NativeScript where
  className _ = "NativeScript"

instance IsBytes NativeScript
instance IsJson NativeScript
instance EncodeAeson NativeScript where
  encodeAeson = cslToAeson

instance DecodeAeson NativeScript where
  decodeAeson = cslFromAeson

instance Show NativeScript where
  show = showViaJson

--------------------------------------------------------------------------------
-- Native script source

foreign import data NativeScriptSource :: Type

foreign import nativeScriptSource_new :: NativeScript -> NativeScriptSource
foreign import nativeScriptSource_newRefInput :: ScriptHash -> TransactionInput -> NativeScriptSource
foreign import nativeScriptSource_setRequiredSigners :: NativeScriptSource -> Ed25519KeyHashes -> Effect Unit

instance IsCsl NativeScriptSource where
  className _ = "NativeScriptSource"

--------------------------------------------------------------------------------
-- Native scripts

foreign import data NativeScripts :: Type

foreign import nativeScripts_new :: Effect NativeScripts

instance IsCsl NativeScripts where
  className _ = "NativeScripts"

instance IsBytes NativeScripts
instance IsJson NativeScripts
instance EncodeAeson NativeScripts where
  encodeAeson = cslToAeson

instance DecodeAeson NativeScripts where
  decodeAeson = cslFromAeson

instance Show NativeScripts where
  show = showViaJson

instance IsListContainer NativeScripts NativeScript

--------------------------------------------------------------------------------
-- Network id

foreign import data NetworkId :: Type

foreign import networkId_testnet :: NetworkId
foreign import networkId_mainnet :: NetworkId
foreign import networkId_kind :: NetworkId -> NetworkIdKind

instance IsCsl NetworkId where
  className _ = "NetworkId"

instance IsBytes NetworkId
instance IsJson NetworkId
instance EncodeAeson NetworkId where
  encodeAeson = cslToAeson

instance DecodeAeson NetworkId where
  decodeAeson = cslFromAeson

instance Show NetworkId where
  show = showViaJson

--------------------------------------------------------------------------------
-- Network info

foreign import data NetworkInfo :: Type

foreign import networkInfo_new :: Number -> Number -> NetworkInfo
foreign import networkInfo_networkId :: NetworkInfo -> Number
foreign import networkInfo_protocolMagic :: NetworkInfo -> Number
foreign import networkInfo_testnetPreview :: NetworkInfo
foreign import networkInfo_testnetPreprod :: NetworkInfo
foreign import networkInfo_mainnet :: NetworkInfo

instance IsCsl NetworkInfo where
  className _ = "NetworkInfo"

--------------------------------------------------------------------------------
-- New constitution action

foreign import data NewConstitutionAction :: Type

foreign import newConstitutionAction_govActionId :: NewConstitutionAction -> Nullable GovernanceActionId
foreign import newConstitutionAction_constitution :: NewConstitutionAction -> Constitution
foreign import newConstitutionAction_new :: Constitution -> NewConstitutionAction
foreign import newConstitutionAction_newWithActionId :: GovernanceActionId -> Constitution -> NewConstitutionAction
foreign import newConstitutionAction_hasScriptHash :: NewConstitutionAction -> Boolean

instance IsCsl NewConstitutionAction where
  className _ = "NewConstitutionAction"

instance IsBytes NewConstitutionAction
instance IsJson NewConstitutionAction
instance EncodeAeson NewConstitutionAction where
  encodeAeson = cslToAeson

instance DecodeAeson NewConstitutionAction where
  decodeAeson = cslFromAeson

instance Show NewConstitutionAction where
  show = showViaJson

--------------------------------------------------------------------------------
-- No confidence action

foreign import data NoConfidenceAction :: Type

foreign import noConfidenceAction_govActionId :: NoConfidenceAction -> Nullable GovernanceActionId
foreign import noConfidenceAction_new :: NoConfidenceAction
foreign import noConfidenceAction_newWithActionId :: GovernanceActionId -> NoConfidenceAction

instance IsCsl NoConfidenceAction where
  className _ = "NoConfidenceAction"

instance IsBytes NoConfidenceAction
instance IsJson NoConfidenceAction
instance EncodeAeson NoConfidenceAction where
  encodeAeson = cslToAeson

instance DecodeAeson NoConfidenceAction where
  decodeAeson = cslFromAeson

instance Show NoConfidenceAction where
  show = showViaJson

--------------------------------------------------------------------------------
-- Nonce

foreign import data Nonce :: Type

foreign import nonce_newIdentity :: Nonce
foreign import nonce_newFromHash :: ByteArray -> Nonce
foreign import nonce_getHash :: Nonce -> Nullable ByteArray

instance IsCsl Nonce where
  className _ = "Nonce"

instance IsBytes Nonce
instance IsJson Nonce
instance EncodeAeson Nonce where
  encodeAeson = cslToAeson

instance DecodeAeson Nonce where
  decodeAeson = cslFromAeson

instance Show Nonce where
  show = showViaJson

--------------------------------------------------------------------------------
-- Operational cert

foreign import data OperationalCert :: Type

foreign import operationalCert_hotVkey :: OperationalCert -> KESVKey
foreign import operationalCert_sequenceNumber :: OperationalCert -> Number
foreign import operationalCert_kesPeriod :: OperationalCert -> Number
foreign import operationalCert_sigma :: OperationalCert -> Ed25519Signature
foreign import operationalCert_new :: KESVKey -> Number -> Number -> Ed25519Signature -> OperationalCert

instance IsCsl OperationalCert where
  className _ = "OperationalCert"

instance IsBytes OperationalCert
instance IsJson OperationalCert
instance EncodeAeson OperationalCert where
  encodeAeson = cslToAeson

instance DecodeAeson OperationalCert where
  decodeAeson = cslFromAeson

instance Show OperationalCert where
  show = showViaJson

--------------------------------------------------------------------------------
-- Output datum

foreign import data OutputDatum :: Type

foreign import outputDatum_newDataHash :: DataHash -> OutputDatum
foreign import outputDatum_newData :: PlutusData -> OutputDatum
foreign import outputDatum_dataHash :: OutputDatum -> Nullable DataHash
foreign import outputDatum_data :: OutputDatum -> Nullable PlutusData

instance IsCsl OutputDatum where
  className _ = "OutputDatum"

--------------------------------------------------------------------------------
-- Parameter change action

foreign import data ParameterChangeAction :: Type

foreign import parameterChangeAction_govActionId :: ParameterChangeAction -> Nullable GovernanceActionId
foreign import parameterChangeAction_protocolParamUpdates :: ParameterChangeAction -> ProtocolParamUpdate
foreign import parameterChangeAction_policyHash :: ParameterChangeAction -> Nullable ScriptHash
foreign import parameterChangeAction_new :: ProtocolParamUpdate -> ParameterChangeAction
foreign import parameterChangeAction_newWithActionId :: GovernanceActionId -> ProtocolParamUpdate -> ParameterChangeAction
foreign import parameterChangeAction_newWithPolicyHash :: ProtocolParamUpdate -> ScriptHash -> ParameterChangeAction
foreign import parameterChangeAction_newWithPolicyHashAndActionId :: GovernanceActionId -> ProtocolParamUpdate -> ScriptHash -> ParameterChangeAction

instance IsCsl ParameterChangeAction where
  className _ = "ParameterChangeAction"

instance IsBytes ParameterChangeAction
instance IsJson ParameterChangeAction
instance EncodeAeson ParameterChangeAction where
  encodeAeson = cslToAeson

instance DecodeAeson ParameterChangeAction where
  decodeAeson = cslFromAeson

instance Show ParameterChangeAction where
  show = showViaJson

--------------------------------------------------------------------------------
-- Plutus data

foreign import data PlutusData :: Type

foreign import plutusData_newConstrPlutusData :: ConstrPlutusData -> PlutusData
foreign import plutusData_newEmptyConstrPlutusData :: BigNum -> PlutusData
foreign import plutusData_newSingleValueConstrPlutusData :: BigNum -> PlutusData -> PlutusData
foreign import plutusData_newMap :: PlutusMap -> PlutusData
foreign import plutusData_newList :: PlutusList -> PlutusData
foreign import plutusData_newInteger :: BigInt -> PlutusData
foreign import plutusData_newBytes :: ByteArray -> PlutusData
foreign import plutusData_kind :: PlutusData -> PlutusDataKind
foreign import plutusData_asConstrPlutusData :: PlutusData -> Nullable ConstrPlutusData
foreign import plutusData_asMap :: PlutusData -> Nullable PlutusMap
foreign import plutusData_asList :: PlutusData -> Nullable PlutusList
foreign import plutusData_asInteger :: PlutusData -> Nullable BigInt
foreign import plutusData_asBytes :: PlutusData -> Nullable ByteArray
foreign import plutusData_fromAddress :: Address -> PlutusData

instance IsCsl PlutusData where
  className _ = "PlutusData"

instance IsBytes PlutusData
instance IsJson PlutusData
instance EncodeAeson PlutusData where
  encodeAeson = cslToAeson

instance DecodeAeson PlutusData where
  decodeAeson = cslFromAeson

instance Show PlutusData where
  show = showViaJson

--------------------------------------------------------------------------------
-- Plutus list

foreign import data PlutusList :: Type

foreign import plutusList_new :: Effect PlutusList

instance IsCsl PlutusList where
  className _ = "PlutusList"

instance IsBytes PlutusList
instance EncodeAeson PlutusList where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson PlutusList where
  decodeAeson = cslFromAesonViaBytes

instance Show PlutusList where
  show = showViaBytes

instance IsListContainer PlutusList PlutusData

--------------------------------------------------------------------------------
-- Plutus map

foreign import data PlutusMap :: Type

foreign import plutusMap_new :: Effect PlutusMap

instance IsCsl PlutusMap where
  className _ = "PlutusMap"

instance IsBytes PlutusMap
instance EncodeAeson PlutusMap where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson PlutusMap where
  decodeAeson = cslFromAesonViaBytes

instance Show PlutusMap where
  show = showViaBytes

instance IsMapContainer PlutusMap PlutusData PlutusData

--------------------------------------------------------------------------------
-- Plutus script

foreign import data PlutusScript :: Type

foreign import plutusScript_new :: ByteArray -> PlutusScript
foreign import plutusScript_newV2 :: ByteArray -> PlutusScript
foreign import plutusScript_newV3 :: ByteArray -> PlutusScript
foreign import plutusScript_newWithVersion :: ByteArray -> Language -> PlutusScript
foreign import plutusScript_bytes :: PlutusScript -> ByteArray
foreign import plutusScript_fromBytesV2 :: ByteArray -> PlutusScript
foreign import plutusScript_fromBytesV3 :: ByteArray -> PlutusScript
foreign import plutusScript_fromBytesWithVersion :: ByteArray -> Language -> PlutusScript
foreign import plutusScript_fromHexWithVersion :: String -> Language -> PlutusScript
foreign import plutusScript_hash :: PlutusScript -> ScriptHash
foreign import plutusScript_languageVersion :: PlutusScript -> Language

instance IsCsl PlutusScript where
  className _ = "PlutusScript"

instance IsBytes PlutusScript
instance EncodeAeson PlutusScript where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson PlutusScript where
  decodeAeson = cslFromAesonViaBytes

instance Show PlutusScript where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Plutus script source

foreign import data PlutusScriptSource :: Type

foreign import plutusScriptSource_new :: PlutusScript -> PlutusScriptSource
foreign import plutusScriptSource_newRefInput :: ScriptHash -> TransactionInput -> Language -> Number -> PlutusScriptSource
foreign import plutusScriptSource_setRequiredSigners :: PlutusScriptSource -> Ed25519KeyHashes -> Effect Unit
foreign import plutusScriptSource_getRefScriptSize :: PlutusScriptSource -> Nullable Number

instance IsCsl PlutusScriptSource where
  className _ = "PlutusScriptSource"

--------------------------------------------------------------------------------
-- Plutus scripts

foreign import data PlutusScripts :: Type

foreign import plutusScripts_new :: Effect PlutusScripts

instance IsCsl PlutusScripts where
  className _ = "PlutusScripts"

instance IsBytes PlutusScripts
instance IsJson PlutusScripts
instance EncodeAeson PlutusScripts where
  encodeAeson = cslToAeson

instance DecodeAeson PlutusScripts where
  decodeAeson = cslFromAeson

instance Show PlutusScripts where
  show = showViaJson

instance IsListContainer PlutusScripts PlutusScript

--------------------------------------------------------------------------------
-- Plutus witness

foreign import data PlutusWitness :: Type

foreign import plutusWitness_new :: PlutusScript -> PlutusData -> Redeemer -> PlutusWitness
foreign import plutusWitness_newWithRef :: PlutusScriptSource -> DatumSource -> Redeemer -> PlutusWitness
foreign import plutusWitness_newWithoutDatum :: PlutusScript -> Redeemer -> PlutusWitness
foreign import plutusWitness_newWithRefWithoutDatum :: PlutusScriptSource -> Redeemer -> PlutusWitness
foreign import plutusWitness_script :: PlutusWitness -> Nullable PlutusScript
foreign import plutusWitness_datum :: PlutusWitness -> Nullable PlutusData
foreign import plutusWitness_redeemer :: PlutusWitness -> Redeemer

instance IsCsl PlutusWitness where
  className _ = "PlutusWitness"

--------------------------------------------------------------------------------
-- Plutus witnesses

foreign import data PlutusWitnesses :: Type

foreign import plutusWitnesses_new :: Effect PlutusWitnesses

instance IsCsl PlutusWitnesses where
  className _ = "PlutusWitnesses"

instance IsListContainer PlutusWitnesses PlutusWitness

--------------------------------------------------------------------------------
-- Pointer

foreign import data Pointer :: Type

foreign import pointer_new :: Number -> Number -> Number -> Pointer
foreign import pointer_newPointer :: BigNum -> BigNum -> BigNum -> Pointer
foreign import pointer_slot :: Pointer -> Number
foreign import pointer_txIndex :: Pointer -> Number
foreign import pointer_certIndex :: Pointer -> Number
foreign import pointer_slotBignum :: Pointer -> BigNum
foreign import pointer_txIndexBignum :: Pointer -> BigNum
foreign import pointer_certIndexBignum :: Pointer -> BigNum

instance IsCsl Pointer where
  className _ = "Pointer"

--------------------------------------------------------------------------------
-- Pointer address

foreign import data PointerAddress :: Type

foreign import pointerAddress_new :: Number -> Credential -> Pointer -> PointerAddress
foreign import pointerAddress_paymentCred :: PointerAddress -> Credential
foreign import pointerAddress_stakePointer :: PointerAddress -> Pointer
foreign import pointerAddress_toAddress :: PointerAddress -> Address
foreign import pointerAddress_fromAddress :: Address -> Nullable PointerAddress

instance IsCsl PointerAddress where
  className _ = "PointerAddress"

--------------------------------------------------------------------------------
-- Pool metadata

foreign import data PoolMetadata :: Type

foreign import poolMetadata_url :: PoolMetadata -> URL
foreign import poolMetadata_poolMetadataHash :: PoolMetadata -> PoolMetadataHash
foreign import poolMetadata_new :: URL -> PoolMetadataHash -> PoolMetadata

instance IsCsl PoolMetadata where
  className _ = "PoolMetadata"

instance IsBytes PoolMetadata
instance IsJson PoolMetadata
instance EncodeAeson PoolMetadata where
  encodeAeson = cslToAeson

instance DecodeAeson PoolMetadata where
  decodeAeson = cslFromAeson

instance Show PoolMetadata where
  show = showViaJson

--------------------------------------------------------------------------------
-- Pool metadata hash

foreign import data PoolMetadataHash :: Type

foreign import poolMetadataHash_toBech32 :: PoolMetadataHash -> String -> String
foreign import poolMetadataHash_fromBech32 :: String -> Nullable PoolMetadataHash

instance IsCsl PoolMetadataHash where
  className _ = "PoolMetadataHash"

instance IsBytes PoolMetadataHash
instance EncodeAeson PoolMetadataHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson PoolMetadataHash where
  decodeAeson = cslFromAesonViaBytes

instance Show PoolMetadataHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Pool params

foreign import data PoolParams :: Type

foreign import poolParams_operator :: PoolParams -> Ed25519KeyHash
foreign import poolParams_vrfKeyhash :: PoolParams -> VRFKeyHash
foreign import poolParams_pledge :: PoolParams -> BigNum
foreign import poolParams_cost :: PoolParams -> BigNum
foreign import poolParams_margin :: PoolParams -> UnitInterval
foreign import poolParams_rewardAccount :: PoolParams -> RewardAddress
foreign import poolParams_poolOwners :: PoolParams -> Ed25519KeyHashes
foreign import poolParams_relays :: PoolParams -> Relays
foreign import poolParams_poolMetadata :: PoolParams -> Nullable PoolMetadata
foreign import poolParams_new :: Ed25519KeyHash -> VRFKeyHash -> BigNum -> BigNum -> UnitInterval -> RewardAddress -> Ed25519KeyHashes -> Relays -> PoolMetadata -> PoolParams

instance IsCsl PoolParams where
  className _ = "PoolParams"

instance IsBytes PoolParams
instance IsJson PoolParams
instance EncodeAeson PoolParams where
  encodeAeson = cslToAeson

instance DecodeAeson PoolParams where
  decodeAeson = cslFromAeson

instance Show PoolParams where
  show = showViaJson

--------------------------------------------------------------------------------
-- Pool registration

foreign import data PoolRegistration :: Type

foreign import poolRegistration_poolParams :: PoolRegistration -> PoolParams
foreign import poolRegistration_new :: PoolParams -> PoolRegistration

instance IsCsl PoolRegistration where
  className _ = "PoolRegistration"

instance IsBytes PoolRegistration
instance IsJson PoolRegistration
instance EncodeAeson PoolRegistration where
  encodeAeson = cslToAeson

instance DecodeAeson PoolRegistration where
  decodeAeson = cslFromAeson

instance Show PoolRegistration where
  show = showViaJson

--------------------------------------------------------------------------------
-- Pool retirement

foreign import data PoolRetirement :: Type

foreign import poolRetirement_poolKeyhash :: PoolRetirement -> Ed25519KeyHash
foreign import poolRetirement_epoch :: PoolRetirement -> Number
foreign import poolRetirement_new :: Ed25519KeyHash -> Number -> PoolRetirement

instance IsCsl PoolRetirement where
  className _ = "PoolRetirement"

instance IsBytes PoolRetirement
instance IsJson PoolRetirement
instance EncodeAeson PoolRetirement where
  encodeAeson = cslToAeson

instance DecodeAeson PoolRetirement where
  decodeAeson = cslFromAeson

instance Show PoolRetirement where
  show = showViaJson

--------------------------------------------------------------------------------
-- Pool voting thresholds

foreign import data PoolVotingThresholds :: Type

foreign import poolVotingThresholds_new :: UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> UnitInterval -> PoolVotingThresholds
foreign import poolVotingThresholds_motionNoConfidence :: PoolVotingThresholds -> UnitInterval
foreign import poolVotingThresholds_committeeNormal :: PoolVotingThresholds -> UnitInterval
foreign import poolVotingThresholds_committeeNoConfidence :: PoolVotingThresholds -> UnitInterval
foreign import poolVotingThresholds_hardForkInitiation :: PoolVotingThresholds -> UnitInterval
foreign import poolVotingThresholds_securityRelevantThreshold :: PoolVotingThresholds -> UnitInterval

instance IsCsl PoolVotingThresholds where
  className _ = "PoolVotingThresholds"

instance IsBytes PoolVotingThresholds
instance IsJson PoolVotingThresholds
instance EncodeAeson PoolVotingThresholds where
  encodeAeson = cslToAeson

instance DecodeAeson PoolVotingThresholds where
  decodeAeson = cslFromAeson

instance Show PoolVotingThresholds where
  show = showViaJson

--------------------------------------------------------------------------------
-- Private key

foreign import data PrivateKey :: Type

foreign import privateKey_free :: PrivateKey -> Nullable Unit
foreign import privateKey_fromHex :: String -> Nullable PrivateKey
foreign import privateKey_toHex :: PrivateKey -> String
foreign import privateKey_sign :: PrivateKey -> ByteArray -> Ed25519Signature
foreign import privateKey_fromNormalBytes :: ByteArray -> Nullable PrivateKey
foreign import privateKey_fromExtendedBytes :: ByteArray -> Nullable PrivateKey
foreign import privateKey_asBytes :: PrivateKey -> ByteArray
foreign import privateKey_toBech32 :: PrivateKey -> String
foreign import privateKey_fromBech32 :: String -> Nullable PrivateKey
foreign import privateKey_generateEd25519extended :: Effect PrivateKey
foreign import privateKey_generateEd25519 :: Effect PrivateKey
foreign import privateKey_toPublic :: PrivateKey -> PublicKey

instance IsCsl PrivateKey where
  className _ = "PrivateKey"

--------------------------------------------------------------------------------
-- Proposed protocol parameter updates

foreign import data ProposedProtocolParameterUpdates :: Type

foreign import proposedProtocolParameterUpdates_new :: Effect ProposedProtocolParameterUpdates

instance IsCsl ProposedProtocolParameterUpdates where
  className _ = "ProposedProtocolParameterUpdates"

instance IsBytes ProposedProtocolParameterUpdates
instance IsJson ProposedProtocolParameterUpdates
instance EncodeAeson ProposedProtocolParameterUpdates where
  encodeAeson = cslToAeson

instance DecodeAeson ProposedProtocolParameterUpdates where
  decodeAeson = cslFromAeson

instance Show ProposedProtocolParameterUpdates where
  show = showViaJson

instance IsMapContainer ProposedProtocolParameterUpdates GenesisHash ProtocolParamUpdate

--------------------------------------------------------------------------------
-- Protocol param update

foreign import data ProtocolParamUpdate :: Type

foreign import protocolParamUpdate_setMinfeeA :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minfeeA :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setMinfeeB :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minfeeB :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setMaxBlockBodySize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxBlockBodySize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setMaxTxSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxTxSize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setMaxBlockHeaderSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxBlockHeaderSize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setKeyDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_keyDeposit :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setPoolDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_poolDeposit :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setMaxEpoch :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxEpoch :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setNOpt :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_nOpt :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setPoolPledgeInfluence :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_poolPledgeInfluence :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_setExpansionRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_expansionRate :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_setTreasuryGrowthRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_treasuryGrowthRate :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_d :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_extraEntropy :: ProtocolParamUpdate -> Nullable Nonce
foreign import protocolParamUpdate_setProtocolVersion :: ProtocolParamUpdate -> ProtocolVersion -> Effect Unit
foreign import protocolParamUpdate_protocolVersion :: ProtocolParamUpdate -> Nullable ProtocolVersion
foreign import protocolParamUpdate_setMinPoolCost :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minPoolCost :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setAdaPerUtxoByte :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_adaPerUtxoByte :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setCostModels :: ProtocolParamUpdate -> Costmdls -> Effect Unit
foreign import protocolParamUpdate_costModels :: ProtocolParamUpdate -> Nullable Costmdls
foreign import protocolParamUpdate_setExecutionCosts :: ProtocolParamUpdate -> ExUnitPrices -> Effect Unit
foreign import protocolParamUpdate_executionCosts :: ProtocolParamUpdate -> Nullable ExUnitPrices
foreign import protocolParamUpdate_setMaxTxExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
foreign import protocolParamUpdate_maxTxExUnits :: ProtocolParamUpdate -> Nullable ExUnits
foreign import protocolParamUpdate_setMaxBlockExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
foreign import protocolParamUpdate_maxBlockExUnits :: ProtocolParamUpdate -> Nullable ExUnits
foreign import protocolParamUpdate_setMaxValueSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxValueSize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setCollateralPercentage :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_collateralPercentage :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setMaxCollateralInputs :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxCollateralInputs :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setPoolVotingThresholds :: ProtocolParamUpdate -> PoolVotingThresholds -> Effect Unit
foreign import protocolParamUpdate_poolVotingThresholds :: ProtocolParamUpdate -> Nullable PoolVotingThresholds
foreign import protocolParamUpdate_setDrepVotingThresholds :: ProtocolParamUpdate -> DrepVotingThresholds -> Effect Unit
foreign import protocolParamUpdate_drepVotingThresholds :: ProtocolParamUpdate -> Nullable DrepVotingThresholds
foreign import protocolParamUpdate_setMinCommitteeSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_minCommitteeSize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setCommitteeTermLimit :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_committeeTermLimit :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setGovernanceActionValidityPeriod :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_governanceActionValidityPeriod :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setGovernanceActionDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_governanceActionDeposit :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setDrepDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_drepDeposit :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setDrepInactivityPeriod :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_drepInactivityPeriod :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setRefScriptCoinsPerByte :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_refScriptCoinsPerByte :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_new :: ProtocolParamUpdate

instance IsCsl ProtocolParamUpdate where
  className _ = "ProtocolParamUpdate"

instance IsBytes ProtocolParamUpdate
instance IsJson ProtocolParamUpdate
instance EncodeAeson ProtocolParamUpdate where
  encodeAeson = cslToAeson

instance DecodeAeson ProtocolParamUpdate where
  decodeAeson = cslFromAeson

instance Show ProtocolParamUpdate where
  show = showViaJson

--------------------------------------------------------------------------------
-- Protocol version

foreign import data ProtocolVersion :: Type

foreign import protocolVersion_major :: ProtocolVersion -> Number
foreign import protocolVersion_minor :: ProtocolVersion -> Number
foreign import protocolVersion_new :: Number -> Number -> ProtocolVersion

instance IsCsl ProtocolVersion where
  className _ = "ProtocolVersion"

instance IsBytes ProtocolVersion
instance IsJson ProtocolVersion
instance EncodeAeson ProtocolVersion where
  encodeAeson = cslToAeson

instance DecodeAeson ProtocolVersion where
  decodeAeson = cslFromAeson

instance Show ProtocolVersion where
  show = showViaJson

--------------------------------------------------------------------------------
-- Public key

foreign import data PublicKey :: Type

foreign import publicKey_free :: PublicKey -> Nullable Unit
foreign import publicKey_fromHex :: String -> Nullable PublicKey
foreign import publicKey_toHex :: PublicKey -> String
foreign import publicKey_hash :: PublicKey -> Ed25519KeyHash
foreign import publicKey_verify :: PublicKey -> ByteArray -> Ed25519Signature -> Boolean
foreign import publicKey_fromBytes :: ByteArray -> Nullable PublicKey
foreign import publicKey_asBytes :: PublicKey -> ByteArray
foreign import publicKey_toBech32 :: PublicKey -> String
foreign import publicKey_fromBech32 :: String -> Nullable PublicKey

instance IsCsl PublicKey where
  className _ = "PublicKey"

--------------------------------------------------------------------------------
-- Redeemer

foreign import data Redeemer :: Type

foreign import redeemer_tag :: Redeemer -> RedeemerTag
foreign import redeemer_index :: Redeemer -> BigNum
foreign import redeemer_data :: Redeemer -> PlutusData
foreign import redeemer_exUnits :: Redeemer -> ExUnits
foreign import redeemer_new :: RedeemerTag -> BigNum -> PlutusData -> ExUnits -> Redeemer

instance IsCsl Redeemer where
  className _ = "Redeemer"

instance IsBytes Redeemer
instance IsJson Redeemer
instance EncodeAeson Redeemer where
  encodeAeson = cslToAeson

instance DecodeAeson Redeemer where
  decodeAeson = cslFromAeson

instance Show Redeemer where
  show = showViaJson

--------------------------------------------------------------------------------
-- Redeemer tag

foreign import data RedeemerTag :: Type

foreign import redeemerTag_newSpend :: RedeemerTag
foreign import redeemerTag_newMint :: RedeemerTag
foreign import redeemerTag_newCert :: RedeemerTag
foreign import redeemerTag_newReward :: RedeemerTag
foreign import redeemerTag_newVote :: RedeemerTag
foreign import redeemerTag_newVotingProposal :: RedeemerTag
foreign import redeemerTag_kind :: RedeemerTag -> RedeemerTagKind

instance IsCsl RedeemerTag where
  className _ = "RedeemerTag"

instance IsBytes RedeemerTag
instance IsJson RedeemerTag
instance EncodeAeson RedeemerTag where
  encodeAeson = cslToAeson

instance DecodeAeson RedeemerTag where
  decodeAeson = cslFromAeson

instance Show RedeemerTag where
  show = showViaJson

--------------------------------------------------------------------------------
-- Redeemers

foreign import data Redeemers :: Type

foreign import redeemers_new :: Effect Redeemers
foreign import redeemers_totalExUnits :: Redeemers -> ExUnits

instance IsCsl Redeemers where
  className _ = "Redeemers"

instance IsBytes Redeemers
instance IsJson Redeemers
instance EncodeAeson Redeemers where
  encodeAeson = cslToAeson

instance DecodeAeson Redeemers where
  decodeAeson = cslFromAeson

instance Show Redeemers where
  show = showViaJson

instance IsListContainer Redeemers Redeemer

--------------------------------------------------------------------------------
-- Relay

foreign import data Relay :: Type

foreign import relay_newSingleHostAddr :: SingleHostAddr -> Relay
foreign import relay_newSingleHostName :: SingleHostName -> Relay
foreign import relay_newMultiHostName :: MultiHostName -> Relay
foreign import relay_kind :: Relay -> RelayKind
foreign import relay_asSingleHostAddr :: Relay -> Nullable SingleHostAddr
foreign import relay_asSingleHostName :: Relay -> Nullable SingleHostName
foreign import relay_asMultiHostName :: Relay -> Nullable MultiHostName

instance IsCsl Relay where
  className _ = "Relay"

instance IsBytes Relay
instance IsJson Relay
instance EncodeAeson Relay where
  encodeAeson = cslToAeson

instance DecodeAeson Relay where
  decodeAeson = cslFromAeson

instance Show Relay where
  show = showViaJson

--------------------------------------------------------------------------------
-- Relays

foreign import data Relays :: Type

foreign import relays_new :: Effect Relays

instance IsCsl Relays where
  className _ = "Relays"

instance IsBytes Relays
instance IsJson Relays
instance EncodeAeson Relays where
  encodeAeson = cslToAeson

instance DecodeAeson Relays where
  decodeAeson = cslFromAeson

instance Show Relays where
  show = showViaJson

instance IsListContainer Relays Relay

--------------------------------------------------------------------------------
-- Reward address

foreign import data RewardAddress :: Type

foreign import rewardAddress_new :: Number -> Credential -> RewardAddress
foreign import rewardAddress_paymentCred :: RewardAddress -> Credential
foreign import rewardAddress_toAddress :: RewardAddress -> Address
foreign import rewardAddress_fromAddress :: Address -> Nullable RewardAddress

instance IsCsl RewardAddress where
  className _ = "RewardAddress"

--------------------------------------------------------------------------------
-- Reward addresses

foreign import data RewardAddresses :: Type

foreign import rewardAddresses_new :: Effect RewardAddresses

instance IsCsl RewardAddresses where
  className _ = "RewardAddresses"

instance IsBytes RewardAddresses
instance IsJson RewardAddresses
instance EncodeAeson RewardAddresses where
  encodeAeson = cslToAeson

instance DecodeAeson RewardAddresses where
  decodeAeson = cslFromAeson

instance Show RewardAddresses where
  show = showViaJson

instance IsListContainer RewardAddresses RewardAddress

--------------------------------------------------------------------------------
-- Script all

foreign import data ScriptAll :: Type

foreign import scriptAll_nativeScripts :: ScriptAll -> NativeScripts
foreign import scriptAll_new :: NativeScripts -> ScriptAll

instance IsCsl ScriptAll where
  className _ = "ScriptAll"

instance IsBytes ScriptAll
instance IsJson ScriptAll
instance EncodeAeson ScriptAll where
  encodeAeson = cslToAeson

instance DecodeAeson ScriptAll where
  decodeAeson = cslFromAeson

instance Show ScriptAll where
  show = showViaJson

--------------------------------------------------------------------------------
-- Script any

foreign import data ScriptAny :: Type

foreign import scriptAny_nativeScripts :: ScriptAny -> NativeScripts
foreign import scriptAny_new :: NativeScripts -> ScriptAny

instance IsCsl ScriptAny where
  className _ = "ScriptAny"

instance IsBytes ScriptAny
instance IsJson ScriptAny
instance EncodeAeson ScriptAny where
  encodeAeson = cslToAeson

instance DecodeAeson ScriptAny where
  decodeAeson = cslFromAeson

instance Show ScriptAny where
  show = showViaJson

--------------------------------------------------------------------------------
-- Script data hash

foreign import data ScriptDataHash :: Type

foreign import scriptDataHash_toBech32 :: ScriptDataHash -> String -> String
foreign import scriptDataHash_fromBech32 :: String -> Nullable ScriptDataHash

instance IsCsl ScriptDataHash where
  className _ = "ScriptDataHash"

instance IsBytes ScriptDataHash
instance EncodeAeson ScriptDataHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson ScriptDataHash where
  decodeAeson = cslFromAesonViaBytes

instance Show ScriptDataHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Script hash

foreign import data ScriptHash :: Type

foreign import scriptHash_toBech32 :: ScriptHash -> String -> String
foreign import scriptHash_fromBech32 :: String -> Nullable ScriptHash

instance IsCsl ScriptHash where
  className _ = "ScriptHash"

instance IsBytes ScriptHash
instance EncodeAeson ScriptHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson ScriptHash where
  decodeAeson = cslFromAesonViaBytes

instance Show ScriptHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Script hashes

foreign import data ScriptHashes :: Type

foreign import scriptHashes_new :: Effect ScriptHashes

instance IsCsl ScriptHashes where
  className _ = "ScriptHashes"

instance IsBytes ScriptHashes
instance IsJson ScriptHashes
instance EncodeAeson ScriptHashes where
  encodeAeson = cslToAeson

instance DecodeAeson ScriptHashes where
  decodeAeson = cslFromAeson

instance Show ScriptHashes where
  show = showViaJson

instance IsListContainer ScriptHashes ScriptHash

--------------------------------------------------------------------------------
-- Script nOf k

foreign import data ScriptNOfK :: Type

foreign import scriptNOfK_n :: ScriptNOfK -> Number
foreign import scriptNOfK_nativeScripts :: ScriptNOfK -> NativeScripts
foreign import scriptNOfK_new :: Number -> NativeScripts -> ScriptNOfK

instance IsCsl ScriptNOfK where
  className _ = "ScriptNOfK"

instance IsBytes ScriptNOfK
instance IsJson ScriptNOfK
instance EncodeAeson ScriptNOfK where
  encodeAeson = cslToAeson

instance DecodeAeson ScriptNOfK where
  decodeAeson = cslFromAeson

instance Show ScriptNOfK where
  show = showViaJson

--------------------------------------------------------------------------------
-- Script pubkey

foreign import data ScriptPubkey :: Type

foreign import scriptPubkey_addrKeyhash :: ScriptPubkey -> Ed25519KeyHash
foreign import scriptPubkey_new :: Ed25519KeyHash -> ScriptPubkey

instance IsCsl ScriptPubkey where
  className _ = "ScriptPubkey"

instance IsBytes ScriptPubkey
instance IsJson ScriptPubkey
instance EncodeAeson ScriptPubkey where
  encodeAeson = cslToAeson

instance DecodeAeson ScriptPubkey where
  decodeAeson = cslFromAeson

instance Show ScriptPubkey where
  show = showViaJson

--------------------------------------------------------------------------------
-- Script ref

foreign import data ScriptRef :: Type

foreign import scriptRef_newNativeScript :: NativeScript -> ScriptRef
foreign import scriptRef_newPlutusScript :: PlutusScript -> ScriptRef
foreign import scriptRef_isNativeScript :: ScriptRef -> Boolean
foreign import scriptRef_isPlutusScript :: ScriptRef -> Boolean
foreign import scriptRef_nativeScript :: ScriptRef -> Nullable NativeScript
foreign import scriptRef_plutusScript :: ScriptRef -> Nullable PlutusScript

instance IsCsl ScriptRef where
  className _ = "ScriptRef"

instance IsBytes ScriptRef
instance IsJson ScriptRef
instance EncodeAeson ScriptRef where
  encodeAeson = cslToAeson

instance DecodeAeson ScriptRef where
  decodeAeson = cslFromAeson

instance Show ScriptRef where
  show = showViaJson

--------------------------------------------------------------------------------
-- Single host addr

foreign import data SingleHostAddr :: Type

foreign import singleHostAddr_port :: SingleHostAddr -> Nullable Number
foreign import singleHostAddr_ipv4 :: SingleHostAddr -> Nullable Ipv4
foreign import singleHostAddr_ipv6 :: SingleHostAddr -> Nullable Ipv6
foreign import singleHostAddr_new :: Number -> Ipv4 -> Ipv6 -> SingleHostAddr

instance IsCsl SingleHostAddr where
  className _ = "SingleHostAddr"

instance IsBytes SingleHostAddr
instance IsJson SingleHostAddr
instance EncodeAeson SingleHostAddr where
  encodeAeson = cslToAeson

instance DecodeAeson SingleHostAddr where
  decodeAeson = cslFromAeson

instance Show SingleHostAddr where
  show = showViaJson

--------------------------------------------------------------------------------
-- Single host name

foreign import data SingleHostName :: Type

foreign import singleHostName_port :: SingleHostName -> Nullable Number
foreign import singleHostName_dnsName :: SingleHostName -> DNSRecordAorAAAA
foreign import singleHostName_new :: Nullable Number -> DNSRecordAorAAAA -> SingleHostName

instance IsCsl SingleHostName where
  className _ = "SingleHostName"

instance IsBytes SingleHostName
instance IsJson SingleHostName
instance EncodeAeson SingleHostName where
  encodeAeson = cslToAeson

instance DecodeAeson SingleHostName where
  decodeAeson = cslFromAeson

instance Show SingleHostName where
  show = showViaJson

--------------------------------------------------------------------------------
-- Stake and vote delegation

foreign import data StakeAndVoteDelegation :: Type

foreign import stakeAndVoteDelegation_stakeCredential :: StakeAndVoteDelegation -> Credential
foreign import stakeAndVoteDelegation_poolKeyhash :: StakeAndVoteDelegation -> Ed25519KeyHash
foreign import stakeAndVoteDelegation_drep :: StakeAndVoteDelegation -> DRep
foreign import stakeAndVoteDelegation_new :: Credential -> Ed25519KeyHash -> DRep -> StakeAndVoteDelegation
foreign import stakeAndVoteDelegation_hasScriptCredentials :: StakeAndVoteDelegation -> Boolean

instance IsCsl StakeAndVoteDelegation where
  className _ = "StakeAndVoteDelegation"

instance IsBytes StakeAndVoteDelegation
instance IsJson StakeAndVoteDelegation
instance EncodeAeson StakeAndVoteDelegation where
  encodeAeson = cslToAeson

instance DecodeAeson StakeAndVoteDelegation where
  decodeAeson = cslFromAeson

instance Show StakeAndVoteDelegation where
  show = showViaJson

--------------------------------------------------------------------------------
-- Stake delegation

foreign import data StakeDelegation :: Type

foreign import stakeDelegation_stakeCredential :: StakeDelegation -> Credential
foreign import stakeDelegation_poolKeyhash :: StakeDelegation -> Ed25519KeyHash
foreign import stakeDelegation_new :: Credential -> Ed25519KeyHash -> StakeDelegation
foreign import stakeDelegation_hasScriptCredentials :: StakeDelegation -> Boolean

instance IsCsl StakeDelegation where
  className _ = "StakeDelegation"

instance IsBytes StakeDelegation
instance IsJson StakeDelegation
instance EncodeAeson StakeDelegation where
  encodeAeson = cslToAeson

instance DecodeAeson StakeDelegation where
  decodeAeson = cslFromAeson

instance Show StakeDelegation where
  show = showViaJson

--------------------------------------------------------------------------------
-- Stake deregistration

foreign import data StakeDeregistration :: Type

foreign import stakeDeregistration_stakeCredential :: StakeDeregistration -> Credential
foreign import stakeDeregistration_coin :: StakeDeregistration -> Nullable BigNum
foreign import stakeDeregistration_new :: Credential -> StakeDeregistration
foreign import stakeDeregistration_newWithCoin :: Credential -> BigNum -> StakeDeregistration
foreign import stakeDeregistration_hasScriptCredentials :: StakeDeregistration -> Boolean

instance IsCsl StakeDeregistration where
  className _ = "StakeDeregistration"

instance IsBytes StakeDeregistration
instance IsJson StakeDeregistration
instance EncodeAeson StakeDeregistration where
  encodeAeson = cslToAeson

instance DecodeAeson StakeDeregistration where
  decodeAeson = cslFromAeson

instance Show StakeDeregistration where
  show = showViaJson

--------------------------------------------------------------------------------
-- Stake registration

foreign import data StakeRegistration :: Type

foreign import stakeRegistration_stakeCredential :: StakeRegistration -> Credential
foreign import stakeRegistration_coin :: StakeRegistration -> Nullable BigNum
foreign import stakeRegistration_new :: Credential -> StakeRegistration
foreign import stakeRegistration_newWithCoin :: Credential -> BigNum -> StakeRegistration
foreign import stakeRegistration_hasScriptCredentials :: StakeRegistration -> Boolean

instance IsCsl StakeRegistration where
  className _ = "StakeRegistration"

instance IsBytes StakeRegistration
instance IsJson StakeRegistration
instance EncodeAeson StakeRegistration where
  encodeAeson = cslToAeson

instance DecodeAeson StakeRegistration where
  decodeAeson = cslFromAeson

instance Show StakeRegistration where
  show = showViaJson

--------------------------------------------------------------------------------
-- Stake registration and delegation

foreign import data StakeRegistrationAndDelegation :: Type

foreign import stakeRegistrationAndDelegation_stakeCredential :: StakeRegistrationAndDelegation -> Credential
foreign import stakeRegistrationAndDelegation_poolKeyhash :: StakeRegistrationAndDelegation -> Ed25519KeyHash
foreign import stakeRegistrationAndDelegation_coin :: StakeRegistrationAndDelegation -> BigNum
foreign import stakeRegistrationAndDelegation_new :: Credential -> Ed25519KeyHash -> BigNum -> StakeRegistrationAndDelegation
foreign import stakeRegistrationAndDelegation_hasScriptCredentials :: StakeRegistrationAndDelegation -> Boolean

instance IsCsl StakeRegistrationAndDelegation where
  className _ = "StakeRegistrationAndDelegation"

instance IsBytes StakeRegistrationAndDelegation
instance IsJson StakeRegistrationAndDelegation
instance EncodeAeson StakeRegistrationAndDelegation where
  encodeAeson = cslToAeson

instance DecodeAeson StakeRegistrationAndDelegation where
  decodeAeson = cslFromAeson

instance Show StakeRegistrationAndDelegation where
  show = showViaJson

--------------------------------------------------------------------------------
-- Stake vote registration and delegation

foreign import data StakeVoteRegistrationAndDelegation :: Type

foreign import stakeVoteRegistrationAndDelegation_stakeCredential :: StakeVoteRegistrationAndDelegation -> Credential
foreign import stakeVoteRegistrationAndDelegation_poolKeyhash :: StakeVoteRegistrationAndDelegation -> Ed25519KeyHash
foreign import stakeVoteRegistrationAndDelegation_drep :: StakeVoteRegistrationAndDelegation -> DRep
foreign import stakeVoteRegistrationAndDelegation_coin :: StakeVoteRegistrationAndDelegation -> BigNum
foreign import stakeVoteRegistrationAndDelegation_new :: Credential -> Ed25519KeyHash -> DRep -> BigNum -> StakeVoteRegistrationAndDelegation
foreign import stakeVoteRegistrationAndDelegation_hasScriptCredentials :: StakeVoteRegistrationAndDelegation -> Boolean

instance IsCsl StakeVoteRegistrationAndDelegation where
  className _ = "StakeVoteRegistrationAndDelegation"

instance IsBytes StakeVoteRegistrationAndDelegation
instance IsJson StakeVoteRegistrationAndDelegation
instance EncodeAeson StakeVoteRegistrationAndDelegation where
  encodeAeson = cslToAeson

instance DecodeAeson StakeVoteRegistrationAndDelegation where
  decodeAeson = cslFromAeson

instance Show StakeVoteRegistrationAndDelegation where
  show = showViaJson

--------------------------------------------------------------------------------
-- Timelock expiry

foreign import data TimelockExpiry :: Type

foreign import timelockExpiry_slot :: TimelockExpiry -> Number
foreign import timelockExpiry_slotBignum :: TimelockExpiry -> BigNum
foreign import timelockExpiry_new :: Number -> TimelockExpiry
foreign import timelockExpiry_newTimelockexpiry :: BigNum -> TimelockExpiry

instance IsCsl TimelockExpiry where
  className _ = "TimelockExpiry"

instance IsBytes TimelockExpiry
instance IsJson TimelockExpiry
instance EncodeAeson TimelockExpiry where
  encodeAeson = cslToAeson

instance DecodeAeson TimelockExpiry where
  decodeAeson = cslFromAeson

instance Show TimelockExpiry where
  show = showViaJson

--------------------------------------------------------------------------------
-- Timelock start

foreign import data TimelockStart :: Type

foreign import timelockStart_slot :: TimelockStart -> Number
foreign import timelockStart_slotBignum :: TimelockStart -> BigNum
foreign import timelockStart_new :: Number -> TimelockStart
foreign import timelockStart_newTimelockstart :: BigNum -> TimelockStart

instance IsCsl TimelockStart where
  className _ = "TimelockStart"

instance IsBytes TimelockStart
instance IsJson TimelockStart
instance EncodeAeson TimelockStart where
  encodeAeson = cslToAeson

instance DecodeAeson TimelockStart where
  decodeAeson = cslFromAeson

instance Show TimelockStart where
  show = showViaJson

--------------------------------------------------------------------------------
-- Transaction

foreign import data Transaction :: Type

foreign import transaction_body :: Transaction -> TransactionBody
foreign import transaction_witnessSet :: Transaction -> TransactionWitnessSet
foreign import transaction_isValid :: Transaction -> Boolean
foreign import transaction_auxiliaryData :: Transaction -> Nullable AuxiliaryData
foreign import transaction_setIsValid :: Transaction -> Boolean -> Effect Unit
foreign import transaction_new :: TransactionBody -> TransactionWitnessSet -> AuxiliaryData -> Transaction

instance IsCsl Transaction where
  className _ = "Transaction"

instance IsBytes Transaction
instance IsJson Transaction
instance EncodeAeson Transaction where
  encodeAeson = cslToAeson

instance DecodeAeson Transaction where
  decodeAeson = cslFromAeson

instance Show Transaction where
  show = showViaJson

--------------------------------------------------------------------------------
-- Transaction batch

foreign import data TransactionBatch :: Type

instance IsCsl TransactionBatch where
  className _ = "TransactionBatch"

--------------------------------------------------------------------------------
-- Transaction batch list

foreign import data TransactionBatchList :: Type

instance IsCsl TransactionBatchList where
  className _ = "TransactionBatchList"

--------------------------------------------------------------------------------
-- Transaction body

foreign import data TransactionBody :: Type

foreign import transactionBody_inputs :: TransactionBody -> TransactionInputs
foreign import transactionBody_outputs :: TransactionBody -> TransactionOutputs
foreign import transactionBody_fee :: TransactionBody -> BigNum
foreign import transactionBody_ttl :: TransactionBody -> Nullable Number
foreign import transactionBody_ttlBignum :: TransactionBody -> Nullable BigNum
foreign import transactionBody_setTtl :: TransactionBody -> BigNum -> Effect Unit
foreign import transactionBody_removeTtl :: TransactionBody -> Nullable Unit
foreign import transactionBody_setCerts :: TransactionBody -> Certificates -> Effect Unit
foreign import transactionBody_certs :: TransactionBody -> Nullable Certificates
foreign import transactionBody_setWithdrawals :: TransactionBody -> Withdrawals -> Effect Unit
foreign import transactionBody_withdrawals :: TransactionBody -> Nullable Withdrawals
foreign import transactionBody_setUpdate :: TransactionBody -> Update -> Effect Unit
foreign import transactionBody_update :: TransactionBody -> Nullable Update
foreign import transactionBody_setAuxiliaryDataHash :: TransactionBody -> AuxiliaryDataHash -> Effect Unit
foreign import transactionBody_auxiliaryDataHash :: TransactionBody -> Nullable AuxiliaryDataHash
foreign import transactionBody_setValidityStartInterval :: TransactionBody -> Number -> Effect Unit
foreign import transactionBody_setValidityStartIntervalBignum :: TransactionBody -> BigNum -> Effect Unit
foreign import transactionBody_validityStartIntervalBignum :: TransactionBody -> Nullable BigNum
foreign import transactionBody_validityStartInterval :: TransactionBody -> Nullable Number
foreign import transactionBody_setMint :: TransactionBody -> Mint -> Effect Unit
foreign import transactionBody_mint :: TransactionBody -> Nullable Mint
foreign import transactionBody_setReferenceInputs :: TransactionBody -> TransactionInputs -> Effect Unit
foreign import transactionBody_referenceInputs :: TransactionBody -> Nullable TransactionInputs
foreign import transactionBody_setScriptDataHash :: TransactionBody -> ScriptDataHash -> Effect Unit
foreign import transactionBody_scriptDataHash :: TransactionBody -> Nullable ScriptDataHash
foreign import transactionBody_setCollateral :: TransactionBody -> TransactionInputs -> Effect Unit
foreign import transactionBody_collateral :: TransactionBody -> Nullable TransactionInputs
foreign import transactionBody_setRequiredSigners :: TransactionBody -> Ed25519KeyHashes -> Effect Unit
foreign import transactionBody_requiredSigners :: TransactionBody -> Nullable Ed25519KeyHashes
foreign import transactionBody_setNetworkId :: TransactionBody -> NetworkId -> Effect Unit
foreign import transactionBody_networkId :: TransactionBody -> Nullable NetworkId
foreign import transactionBody_setCollateralReturn :: TransactionBody -> TransactionOutput -> Effect Unit
foreign import transactionBody_collateralReturn :: TransactionBody -> Nullable TransactionOutput
foreign import transactionBody_setTotalCollateral :: TransactionBody -> BigNum -> Effect Unit
foreign import transactionBody_totalCollateral :: TransactionBody -> Nullable BigNum
foreign import transactionBody_setVotingProcedures :: TransactionBody -> VotingProcedures -> Effect Unit
foreign import transactionBody_votingProcedures :: TransactionBody -> Nullable VotingProcedures
foreign import transactionBody_setVotingProposals :: TransactionBody -> VotingProposals -> Effect Unit
foreign import transactionBody_votingProposals :: TransactionBody -> Nullable VotingProposals
foreign import transactionBody_setDonation :: TransactionBody -> BigNum -> Effect Unit
foreign import transactionBody_donation :: TransactionBody -> Nullable BigNum
foreign import transactionBody_setCurrentTreasuryValue :: TransactionBody -> BigNum -> Effect Unit
foreign import transactionBody_currentTreasuryValue :: TransactionBody -> Nullable BigNum
foreign import transactionBody_new :: TransactionInputs -> TransactionOutputs -> BigNum -> Number -> TransactionBody
foreign import transactionBody_newTxBody :: TransactionInputs -> TransactionOutputs -> BigNum -> TransactionBody

instance IsCsl TransactionBody where
  className _ = "TransactionBody"

instance IsBytes TransactionBody
instance IsJson TransactionBody
instance EncodeAeson TransactionBody where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionBody where
  decodeAeson = cslFromAeson

instance Show TransactionBody where
  show = showViaJson

--------------------------------------------------------------------------------
-- Transaction hash

foreign import data TransactionHash :: Type

foreign import transactionHash_toBech32 :: TransactionHash -> String -> String
foreign import transactionHash_fromBech32 :: String -> Nullable TransactionHash

instance IsCsl TransactionHash where
  className _ = "TransactionHash"

instance IsBytes TransactionHash
instance EncodeAeson TransactionHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson TransactionHash where
  decodeAeson = cslFromAesonViaBytes

instance Show TransactionHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Transaction input

foreign import data TransactionInput :: Type

foreign import transactionInput_transactionId :: TransactionInput -> TransactionHash
foreign import transactionInput_index :: TransactionInput -> Number
foreign import transactionInput_new :: TransactionHash -> Number -> TransactionInput

instance IsCsl TransactionInput where
  className _ = "TransactionInput"

instance IsBytes TransactionInput
instance IsJson TransactionInput
instance EncodeAeson TransactionInput where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionInput where
  decodeAeson = cslFromAeson

instance Show TransactionInput where
  show = showViaJson

--------------------------------------------------------------------------------
-- Transaction inputs

foreign import data TransactionInputs :: Type

foreign import transactionInputs_new :: Effect TransactionInputs
foreign import transactionInputs_toOption :: TransactionInputs -> Nullable TransactionInputs

instance IsCsl TransactionInputs where
  className _ = "TransactionInputs"

instance IsBytes TransactionInputs
instance IsJson TransactionInputs
instance EncodeAeson TransactionInputs where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionInputs where
  decodeAeson = cslFromAeson

instance Show TransactionInputs where
  show = showViaJson

instance IsListContainer TransactionInputs TransactionInput

--------------------------------------------------------------------------------
-- Transaction metadatum

foreign import data TransactionMetadatum :: Type

foreign import transactionMetadatum_newMap :: MetadataMap -> TransactionMetadatum
foreign import transactionMetadatum_newList :: MetadataList -> TransactionMetadatum
foreign import transactionMetadatum_newInt :: Int -> TransactionMetadatum
foreign import transactionMetadatum_newBytes :: ByteArray -> TransactionMetadatum
foreign import transactionMetadatum_newText :: String -> TransactionMetadatum
foreign import transactionMetadatum_kind :: TransactionMetadatum -> TransactionMetadatumKind
foreign import transactionMetadatum_asMap :: TransactionMetadatum -> Nullable MetadataMap
foreign import transactionMetadatum_asList :: TransactionMetadatum -> Nullable MetadataList
foreign import transactionMetadatum_asInt :: TransactionMetadatum -> Nullable Int
foreign import transactionMetadatum_asBytes :: TransactionMetadatum -> Nullable ByteArray
foreign import transactionMetadatum_asText :: TransactionMetadatum -> Nullable String

instance IsCsl TransactionMetadatum where
  className _ = "TransactionMetadatum"

instance IsBytes TransactionMetadatum
instance EncodeAeson TransactionMetadatum where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson TransactionMetadatum where
  decodeAeson = cslFromAesonViaBytes

instance Show TransactionMetadatum where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Transaction metadatum labels

foreign import data TransactionMetadatumLabels :: Type

foreign import transactionMetadatumLabels_new :: Effect TransactionMetadatumLabels

instance IsCsl TransactionMetadatumLabels where
  className _ = "TransactionMetadatumLabels"

instance IsBytes TransactionMetadatumLabels
instance EncodeAeson TransactionMetadatumLabels where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson TransactionMetadatumLabels where
  decodeAeson = cslFromAesonViaBytes

instance Show TransactionMetadatumLabels where
  show = showViaBytes

instance IsListContainer TransactionMetadatumLabels BigNum

--------------------------------------------------------------------------------
-- Transaction output

foreign import data TransactionOutput :: Type

foreign import transactionOutput_address :: TransactionOutput -> Address
foreign import transactionOutput_amount :: TransactionOutput -> Value
foreign import transactionOutput_dataHash :: TransactionOutput -> Nullable DataHash
foreign import transactionOutput_plutusData :: TransactionOutput -> Nullable PlutusData
foreign import transactionOutput_scriptRef :: TransactionOutput -> Nullable ScriptRef
foreign import transactionOutput_setScriptRef :: TransactionOutput -> ScriptRef -> Effect Unit
foreign import transactionOutput_setPlutusData :: TransactionOutput -> PlutusData -> Effect Unit
foreign import transactionOutput_setDataHash :: TransactionOutput -> DataHash -> Effect Unit
foreign import transactionOutput_hasPlutusData :: TransactionOutput -> Boolean
foreign import transactionOutput_hasDataHash :: TransactionOutput -> Boolean
foreign import transactionOutput_hasScriptRef :: TransactionOutput -> Boolean
foreign import transactionOutput_new :: Address -> Value -> TransactionOutput
foreign import transactionOutput_serializationFormat :: TransactionOutput -> Nullable CborContainerType

instance IsCsl TransactionOutput where
  className _ = "TransactionOutput"

instance IsBytes TransactionOutput
instance IsJson TransactionOutput
instance EncodeAeson TransactionOutput where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionOutput where
  decodeAeson = cslFromAeson

instance Show TransactionOutput where
  show = showViaJson

--------------------------------------------------------------------------------
-- Transaction outputs

foreign import data TransactionOutputs :: Type

foreign import transactionOutputs_new :: Effect TransactionOutputs

instance IsCsl TransactionOutputs where
  className _ = "TransactionOutputs"

instance IsBytes TransactionOutputs
instance IsJson TransactionOutputs
instance EncodeAeson TransactionOutputs where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionOutputs where
  decodeAeson = cslFromAeson

instance Show TransactionOutputs where
  show = showViaJson

instance IsListContainer TransactionOutputs TransactionOutput

--------------------------------------------------------------------------------
-- Transaction unspent output

foreign import data TransactionUnspentOutput :: Type

foreign import transactionUnspentOutput_new :: TransactionInput -> TransactionOutput -> TransactionUnspentOutput
foreign import transactionUnspentOutput_input :: TransactionUnspentOutput -> TransactionInput
foreign import transactionUnspentOutput_output :: TransactionUnspentOutput -> TransactionOutput

instance IsCsl TransactionUnspentOutput where
  className _ = "TransactionUnspentOutput"

instance IsBytes TransactionUnspentOutput
instance IsJson TransactionUnspentOutput
instance EncodeAeson TransactionUnspentOutput where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionUnspentOutput where
  decodeAeson = cslFromAeson

instance Show TransactionUnspentOutput where
  show = showViaJson

--------------------------------------------------------------------------------
-- Transaction unspent outputs

foreign import data TransactionUnspentOutputs :: Type

foreign import transactionUnspentOutputs_new :: Effect TransactionUnspentOutputs

instance IsCsl TransactionUnspentOutputs where
  className _ = "TransactionUnspentOutputs"

instance IsJson TransactionUnspentOutputs
instance EncodeAeson TransactionUnspentOutputs where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionUnspentOutputs where
  decodeAeson = cslFromAeson

instance Show TransactionUnspentOutputs where
  show = showViaJson

instance IsListContainer TransactionUnspentOutputs TransactionUnspentOutput

--------------------------------------------------------------------------------
-- Transaction witness set

foreign import data TransactionWitnessSet :: Type

foreign import transactionWitnessSet_setVkeys :: TransactionWitnessSet -> Vkeywitnesses -> Effect Unit
foreign import transactionWitnessSet_vkeys :: TransactionWitnessSet -> Nullable Vkeywitnesses
foreign import transactionWitnessSet_setNativeScripts :: TransactionWitnessSet -> NativeScripts -> Effect Unit
foreign import transactionWitnessSet_nativeScripts :: TransactionWitnessSet -> Nullable NativeScripts
foreign import transactionWitnessSet_setBootstraps :: TransactionWitnessSet -> BootstrapWitnesses -> Effect Unit
foreign import transactionWitnessSet_bootstraps :: TransactionWitnessSet -> Nullable BootstrapWitnesses
foreign import transactionWitnessSet_setPlutusScripts :: TransactionWitnessSet -> PlutusScripts -> Effect Unit
foreign import transactionWitnessSet_plutusScripts :: TransactionWitnessSet -> Nullable PlutusScripts
foreign import transactionWitnessSet_setPlutusData :: TransactionWitnessSet -> PlutusList -> Effect Unit
foreign import transactionWitnessSet_plutusData :: TransactionWitnessSet -> Nullable PlutusList
foreign import transactionWitnessSet_setRedeemers :: TransactionWitnessSet -> Redeemers -> Effect Unit
foreign import transactionWitnessSet_redeemers :: TransactionWitnessSet -> Nullable Redeemers
foreign import transactionWitnessSet_new :: Effect TransactionWitnessSet

instance IsCsl TransactionWitnessSet where
  className _ = "TransactionWitnessSet"

instance IsBytes TransactionWitnessSet
instance IsJson TransactionWitnessSet
instance EncodeAeson TransactionWitnessSet where
  encodeAeson = cslToAeson

instance DecodeAeson TransactionWitnessSet where
  decodeAeson = cslFromAeson

instance Show TransactionWitnessSet where
  show = showViaJson

--------------------------------------------------------------------------------
-- Treasury withdrawals

foreign import data TreasuryWithdrawals :: Type

foreign import treasuryWithdrawals_new :: TreasuryWithdrawals

instance IsCsl TreasuryWithdrawals where
  className _ = "TreasuryWithdrawals"

instance IsJson TreasuryWithdrawals
instance EncodeAeson TreasuryWithdrawals where
  encodeAeson = cslToAeson

instance DecodeAeson TreasuryWithdrawals where
  decodeAeson = cslFromAeson

instance Show TreasuryWithdrawals where
  show = showViaJson

instance IsMapContainer TreasuryWithdrawals RewardAddress BigNum

--------------------------------------------------------------------------------
-- Treasury withdrawals action

foreign import data TreasuryWithdrawalsAction :: Type

foreign import treasuryWithdrawalsAction_withdrawals :: TreasuryWithdrawalsAction -> TreasuryWithdrawals
foreign import treasuryWithdrawalsAction_policyHash :: TreasuryWithdrawalsAction -> Nullable ScriptHash
foreign import treasuryWithdrawalsAction_new :: TreasuryWithdrawals -> TreasuryWithdrawalsAction
foreign import treasuryWithdrawalsAction_newWithPolicyHash :: TreasuryWithdrawals -> ScriptHash -> TreasuryWithdrawalsAction

instance IsCsl TreasuryWithdrawalsAction where
  className _ = "TreasuryWithdrawalsAction"

instance IsBytes TreasuryWithdrawalsAction
instance IsJson TreasuryWithdrawalsAction
instance EncodeAeson TreasuryWithdrawalsAction where
  encodeAeson = cslToAeson

instance DecodeAeson TreasuryWithdrawalsAction where
  decodeAeson = cslFromAeson

instance Show TreasuryWithdrawalsAction where
  show = showViaJson

--------------------------------------------------------------------------------
-- URL

foreign import data URL :: Type

foreign import url_new :: String -> URL
foreign import url_url :: URL -> String

instance IsCsl URL where
  className _ = "URL"

instance IsBytes URL
instance IsJson URL
instance EncodeAeson URL where
  encodeAeson = cslToAeson

instance DecodeAeson URL where
  decodeAeson = cslFromAeson

instance Show URL where
  show = showViaJson

--------------------------------------------------------------------------------
-- Unit interval

foreign import data UnitInterval :: Type

foreign import unitInterval_numerator :: UnitInterval -> BigNum
foreign import unitInterval_denominator :: UnitInterval -> BigNum
foreign import unitInterval_new :: BigNum -> BigNum -> UnitInterval

instance IsCsl UnitInterval where
  className _ = "UnitInterval"

instance IsBytes UnitInterval
instance IsJson UnitInterval
instance EncodeAeson UnitInterval where
  encodeAeson = cslToAeson

instance DecodeAeson UnitInterval where
  decodeAeson = cslFromAeson

instance Show UnitInterval where
  show = showViaJson

--------------------------------------------------------------------------------
-- Update

foreign import data Update :: Type

foreign import update_proposedProtocolParameterUpdates :: Update -> ProposedProtocolParameterUpdates
foreign import update_epoch :: Update -> Number
foreign import update_new :: ProposedProtocolParameterUpdates -> Number -> Update

instance IsCsl Update where
  className _ = "Update"

instance IsBytes Update
instance IsJson Update
instance EncodeAeson Update where
  encodeAeson = cslToAeson

instance DecodeAeson Update where
  decodeAeson = cslFromAeson

instance Show Update where
  show = showViaJson

--------------------------------------------------------------------------------
-- Update committee action

foreign import data UpdateCommitteeAction :: Type

foreign import updateCommitteeAction_govActionId :: UpdateCommitteeAction -> Nullable GovernanceActionId
foreign import updateCommitteeAction_committee :: UpdateCommitteeAction -> Committee
foreign import updateCommitteeAction_membersToRemove :: UpdateCommitteeAction -> Credentials
foreign import updateCommitteeAction_new :: Committee -> Credentials -> UpdateCommitteeAction
foreign import updateCommitteeAction_newWithActionId :: GovernanceActionId -> Committee -> Credentials -> UpdateCommitteeAction

instance IsCsl UpdateCommitteeAction where
  className _ = "UpdateCommitteeAction"

instance IsBytes UpdateCommitteeAction
instance IsJson UpdateCommitteeAction
instance EncodeAeson UpdateCommitteeAction where
  encodeAeson = cslToAeson

instance DecodeAeson UpdateCommitteeAction where
  decodeAeson = cslFromAeson

instance Show UpdateCommitteeAction where
  show = showViaJson

--------------------------------------------------------------------------------
-- VRFCert

foreign import data VRFCert :: Type

foreign import vrfCert_output :: VRFCert -> ByteArray
foreign import vrfCert_proof :: VRFCert -> ByteArray
foreign import vrfCert_new :: ByteArray -> ByteArray -> VRFCert

instance IsCsl VRFCert where
  className _ = "VRFCert"

instance IsBytes VRFCert
instance IsJson VRFCert
instance EncodeAeson VRFCert where
  encodeAeson = cslToAeson

instance DecodeAeson VRFCert where
  decodeAeson = cslFromAeson

instance Show VRFCert where
  show = showViaJson

--------------------------------------------------------------------------------
-- VRFKey hash

foreign import data VRFKeyHash :: Type

foreign import vrfKeyHash_toBech32 :: VRFKeyHash -> String -> String
foreign import vrfKeyHash_fromBech32 :: String -> Nullable VRFKeyHash

instance IsCsl VRFKeyHash where
  className _ = "VRFKeyHash"

instance IsBytes VRFKeyHash
instance EncodeAeson VRFKeyHash where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson VRFKeyHash where
  decodeAeson = cslFromAesonViaBytes

instance Show VRFKeyHash where
  show = showViaBytes

--------------------------------------------------------------------------------
-- VRFVKey

foreign import data VRFVKey :: Type

foreign import vrfvKey_toBech32 :: VRFVKey -> String -> String
foreign import vrfvKey_fromBech32 :: String -> Nullable VRFVKey

instance IsCsl VRFVKey where
  className _ = "VRFVKey"

instance IsBytes VRFVKey
instance EncodeAeson VRFVKey where
  encodeAeson = cslToAesonViaBytes

instance DecodeAeson VRFVKey where
  decodeAeson = cslFromAesonViaBytes

instance Show VRFVKey where
  show = showViaBytes

--------------------------------------------------------------------------------
-- Value

foreign import data Value :: Type

foreign import value_new :: BigNum -> Value
foreign import value_newFromAssets :: MultiAsset -> Value
foreign import value_newWithAssets :: BigNum -> MultiAsset -> Value
foreign import value_zero :: Value
foreign import value_isZero :: Value -> Boolean
foreign import value_coin :: Value -> BigNum
foreign import value_setCoin :: Value -> BigNum -> Effect Unit
foreign import value_multiasset :: Value -> Nullable MultiAsset
foreign import value_setMultiasset :: Value -> MultiAsset -> Effect Unit
foreign import value_checkedAdd :: Value -> Value -> Nullable Value
foreign import value_checkedSub :: Value -> Value -> Nullable Value
foreign import value_clampedSub :: Value -> Value -> Value
foreign import value_compare :: Value -> Value -> Nullable Number

instance IsCsl Value where
  className _ = "Value"

instance IsBytes Value
instance IsJson Value
instance EncodeAeson Value where
  encodeAeson = cslToAeson

instance DecodeAeson Value where
  decodeAeson = cslFromAeson

instance Show Value where
  show = showViaJson

--------------------------------------------------------------------------------
-- Vkey

foreign import data Vkey :: Type

foreign import vkey_new :: PublicKey -> Vkey
foreign import vkey_publicKey :: Vkey -> PublicKey

instance IsCsl Vkey where
  className _ = "Vkey"

instance IsBytes Vkey
instance IsJson Vkey
instance EncodeAeson Vkey where
  encodeAeson = cslToAeson

instance DecodeAeson Vkey where
  decodeAeson = cslFromAeson

instance Show Vkey where
  show = showViaJson

--------------------------------------------------------------------------------
-- Vkeys

foreign import data Vkeys :: Type

foreign import vkeys_new :: Effect Vkeys

instance IsCsl Vkeys where
  className _ = "Vkeys"

instance IsListContainer Vkeys Vkey

--------------------------------------------------------------------------------
-- Vkeywitness

foreign import data Vkeywitness :: Type

foreign import vkeywitness_new :: Vkey -> Ed25519Signature -> Vkeywitness
foreign import vkeywitness_vkey :: Vkeywitness -> Vkey
foreign import vkeywitness_signature :: Vkeywitness -> Ed25519Signature

instance IsCsl Vkeywitness where
  className _ = "Vkeywitness"

instance IsBytes Vkeywitness
instance IsJson Vkeywitness
instance EncodeAeson Vkeywitness where
  encodeAeson = cslToAeson

instance DecodeAeson Vkeywitness where
  decodeAeson = cslFromAeson

instance Show Vkeywitness where
  show = showViaJson

--------------------------------------------------------------------------------
-- Vkeywitnesses

foreign import data Vkeywitnesses :: Type

foreign import vkeywitnesses_new :: Effect Vkeywitnesses

instance IsCsl Vkeywitnesses where
  className _ = "Vkeywitnesses"

instance IsBytes Vkeywitnesses
instance IsJson Vkeywitnesses
instance EncodeAeson Vkeywitnesses where
  encodeAeson = cslToAeson

instance DecodeAeson Vkeywitnesses where
  decodeAeson = cslFromAeson

instance Show Vkeywitnesses where
  show = showViaJson

instance IsListContainer Vkeywitnesses Vkeywitness

--------------------------------------------------------------------------------
-- Vote delegation

foreign import data VoteDelegation :: Type

foreign import voteDelegation_stakeCredential :: VoteDelegation -> Credential
foreign import voteDelegation_drep :: VoteDelegation -> DRep
foreign import voteDelegation_new :: Credential -> DRep -> VoteDelegation
foreign import voteDelegation_hasScriptCredentials :: VoteDelegation -> Boolean

instance IsCsl VoteDelegation where
  className _ = "VoteDelegation"

instance IsBytes VoteDelegation
instance IsJson VoteDelegation
instance EncodeAeson VoteDelegation where
  encodeAeson = cslToAeson

instance DecodeAeson VoteDelegation where
  decodeAeson = cslFromAeson

instance Show VoteDelegation where
  show = showViaJson

--------------------------------------------------------------------------------
-- Vote registration and delegation

foreign import data VoteRegistrationAndDelegation :: Type

foreign import voteRegistrationAndDelegation_stakeCredential :: VoteRegistrationAndDelegation -> Credential
foreign import voteRegistrationAndDelegation_drep :: VoteRegistrationAndDelegation -> DRep
foreign import voteRegistrationAndDelegation_coin :: VoteRegistrationAndDelegation -> BigNum
foreign import voteRegistrationAndDelegation_new :: Credential -> DRep -> BigNum -> VoteRegistrationAndDelegation
foreign import voteRegistrationAndDelegation_hasScriptCredentials :: VoteRegistrationAndDelegation -> Boolean

instance IsCsl VoteRegistrationAndDelegation where
  className _ = "VoteRegistrationAndDelegation"

instance IsBytes VoteRegistrationAndDelegation
instance IsJson VoteRegistrationAndDelegation
instance EncodeAeson VoteRegistrationAndDelegation where
  encodeAeson = cslToAeson

instance DecodeAeson VoteRegistrationAndDelegation where
  decodeAeson = cslFromAeson

instance Show VoteRegistrationAndDelegation where
  show = showViaJson

--------------------------------------------------------------------------------
-- Voter

foreign import data Voter :: Type

foreign import voter_newConstitutionalCommitteeHotKey :: Credential -> Voter
foreign import voter_newDrep :: Credential -> Voter
foreign import voter_newStakingPool :: Ed25519KeyHash -> Voter
foreign import voter_kind :: Voter -> VoterKind
foreign import voter_toConstitutionalCommitteeHotCred :: Voter -> Nullable Credential
foreign import voter_toDrepCred :: Voter -> Nullable Credential
foreign import voter_toStakingPoolKeyHash :: Voter -> Nullable Ed25519KeyHash
foreign import voter_hasScriptCredentials :: Voter -> Boolean
foreign import voter_toKeyHash :: Voter -> Nullable Ed25519KeyHash

instance IsCsl Voter where
  className _ = "Voter"

instance IsBytes Voter
instance IsJson Voter
instance EncodeAeson Voter where
  encodeAeson = cslToAeson

instance DecodeAeson Voter where
  decodeAeson = cslFromAeson

instance Show Voter where
  show = showViaJson

--------------------------------------------------------------------------------
-- Voters

foreign import data Voters :: Type

foreign import voters_new :: Voters

instance IsCsl Voters where
  className _ = "Voters"

instance IsJson Voters
instance EncodeAeson Voters where
  encodeAeson = cslToAeson

instance DecodeAeson Voters where
  decodeAeson = cslFromAeson

instance Show Voters where
  show = showViaJson

instance IsListContainer Voters Voter

--------------------------------------------------------------------------------
-- Voting procedure

foreign import data VotingProcedure :: Type

foreign import votingProcedure_new :: VoteKind -> VotingProcedure
foreign import votingProcedure_newWithAnchor :: VoteKind -> Anchor -> VotingProcedure
foreign import votingProcedure_voteKind :: VotingProcedure -> VoteKind
foreign import votingProcedure_anchor :: VotingProcedure -> Nullable Anchor

instance IsCsl VotingProcedure where
  className _ = "VotingProcedure"

instance IsBytes VotingProcedure
instance IsJson VotingProcedure
instance EncodeAeson VotingProcedure where
  encodeAeson = cslToAeson

instance DecodeAeson VotingProcedure where
  decodeAeson = cslFromAeson

instance Show VotingProcedure where
  show = showViaJson

--------------------------------------------------------------------------------
-- Voting procedures

foreign import data VotingProcedures :: Type

foreign import votingProcedures_free :: VotingProcedures -> Nullable Unit
foreign import votingProcedures_toBytes :: VotingProcedures -> ByteArray
foreign import votingProcedures_fromBytes :: ByteArray -> Nullable VotingProcedures
foreign import votingProcedures_toHex :: VotingProcedures -> String
foreign import votingProcedures_fromHex :: String -> Nullable VotingProcedures
foreign import votingProcedures_toJson :: VotingProcedures -> String
foreign import votingProcedures_fromJson :: String -> Nullable VotingProcedures
foreign import votingProcedures_new :: Effect VotingProcedures
foreign import votingProcedures_insert :: VotingProcedures -> Voter -> GovernanceActionId -> VotingProcedure -> Effect Unit
foreign import votingProcedures_get :: VotingProcedures -> Voter -> GovernanceActionId -> Effect ((Nullable VotingProcedure))
foreign import votingProcedures_getVoters :: VotingProcedures -> Effect Voters
foreign import votingProcedures_getGovernanceActionIdsByVoter :: VotingProcedures -> Voter -> Effect GovernanceActionIds

instance IsCsl VotingProcedures where
  className _ = "VotingProcedures"

instance IsBytes VotingProcedures
instance IsJson VotingProcedures
instance EncodeAeson VotingProcedures where
  encodeAeson = cslToAeson

instance DecodeAeson VotingProcedures where
  decodeAeson = cslFromAeson

instance Show VotingProcedures where
  show = showViaJson

--------------------------------------------------------------------------------
-- Voting proposal

foreign import data VotingProposal :: Type

foreign import votingProposal_governanceAction :: VotingProposal -> GovernanceAction
foreign import votingProposal_anchor :: VotingProposal -> Anchor
foreign import votingProposal_rewardAccount :: VotingProposal -> RewardAddress
foreign import votingProposal_deposit :: VotingProposal -> BigNum
foreign import votingProposal_new :: GovernanceAction -> Anchor -> RewardAddress -> BigNum -> VotingProposal

instance IsCsl VotingProposal where
  className _ = "VotingProposal"

instance IsBytes VotingProposal
instance IsJson VotingProposal
instance EncodeAeson VotingProposal where
  encodeAeson = cslToAeson

instance DecodeAeson VotingProposal where
  decodeAeson = cslFromAeson

instance Show VotingProposal where
  show = showViaJson

--------------------------------------------------------------------------------
-- Voting proposals

foreign import data VotingProposals :: Type

foreign import votingProposals_new :: VotingProposals

instance IsCsl VotingProposals where
  className _ = "VotingProposals"

instance IsBytes VotingProposals
instance IsJson VotingProposals
instance EncodeAeson VotingProposals where
  encodeAeson = cslToAeson

instance DecodeAeson VotingProposals where
  decodeAeson = cslFromAeson

instance Show VotingProposals where
  show = showViaJson

instance IsListContainer VotingProposals VotingProposal

--------------------------------------------------------------------------------
-- Withdrawals

foreign import data Withdrawals :: Type

foreign import withdrawals_new :: Effect Withdrawals

instance IsCsl Withdrawals where
  className _ = "Withdrawals"

instance IsBytes Withdrawals
instance IsJson Withdrawals
instance EncodeAeson Withdrawals where
  encodeAeson = cslToAeson

instance DecodeAeson Withdrawals where
  decodeAeson = cslFromAeson

instance Show Withdrawals where
  show = showViaJson

instance IsMapContainer Withdrawals RewardAddress BigNum

-- enums

--------------------------------------------------------------------------------
-- RedeemerTagKind

foreign import data RedeemerTagKind :: Type

data RedeemerTagKindValues
  = RedeemerTagKind_Spend
  | RedeemerTagKind_Mint
  | RedeemerTagKind_Cert
  | RedeemerTagKind_Reward
  | RedeemerTagKind_Vote
  | RedeemerTagKind_VotingProposal

derive instance Generic RedeemerTagKindValues _
instance IsCslEnum RedeemerTagKindValues RedeemerTagKind
instance Show RedeemerTagKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- CoinSelectionStrategyCIP2

foreign import data CoinSelectionStrategyCIP2 :: Type

data CoinSelectionStrategyCIP2Values
  = CoinSelectionStrategyCIP2_LargestFirst
  | CoinSelectionStrategyCIP2_RandomImprove
  | CoinSelectionStrategyCIP2_LargestFirstMultiAsset
  | CoinSelectionStrategyCIP2_RandomImproveMultiAsset

derive instance Generic CoinSelectionStrategyCIP2Values _
instance IsCslEnum CoinSelectionStrategyCIP2Values CoinSelectionStrategyCIP2
instance Show CoinSelectionStrategyCIP2Values where
  show = genericShow

--------------------------------------------------------------------------------
-- VoteKind

foreign import data VoteKind :: Type

data VoteKindValues
  = VoteKind_No
  | VoteKind_Yes
  | VoteKind_Abstain

derive instance Generic VoteKindValues _
instance IsCslEnum VoteKindValues VoteKind
instance Show VoteKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- VoterKind

foreign import data VoterKind :: Type

data VoterKindValues
  = VoterKind_ConstitutionalCommitteeHotKeyHash
  | VoterKind_ConstitutionalCommitteeHotScriptHash
  | VoterKind_DRepKeyHash
  | VoterKind_DRepScriptHash
  | VoterKind_StakingPoolKeyHash

derive instance Generic VoterKindValues _
instance IsCslEnum VoterKindValues VoterKind
instance Show VoterKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- RelayKind

foreign import data RelayKind :: Type

data RelayKindValues
  = RelayKind_SingleHostAddr
  | RelayKind_SingleHostName
  | RelayKind_MultiHostName

derive instance Generic RelayKindValues _
instance IsCslEnum RelayKindValues RelayKind
instance Show RelayKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- ScriptSchema

foreign import data ScriptSchema :: Type

data ScriptSchemaValues
  = ScriptSchema_Wallet
  | ScriptSchema_Node

derive instance Generic ScriptSchemaValues _
instance IsCslEnum ScriptSchemaValues ScriptSchema
instance Show ScriptSchemaValues where
  show = genericShow

--------------------------------------------------------------------------------
-- GovernanceActionKind

foreign import data GovernanceActionKind :: Type

data GovernanceActionKindValues
  = GovernanceActionKind_ParameterChangeAction
  | GovernanceActionKind_HardForkInitiationAction
  | GovernanceActionKind_TreasuryWithdrawalsAction
  | GovernanceActionKind_NoConfidenceAction
  | GovernanceActionKind_UpdateCommitteeAction
  | GovernanceActionKind_NewConstitutionAction
  | GovernanceActionKind_InfoAction

derive instance Generic GovernanceActionKindValues _
instance IsCslEnum GovernanceActionKindValues GovernanceActionKind
instance Show GovernanceActionKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- AddressKind

foreign import data AddressKind :: Type

data AddressKindValues
  = AddressKind_Base
  | AddressKind_Pointer
  | AddressKind_Enterprise
  | AddressKind_Reward
  | AddressKind_Byron
  | AddressKind_Malformed

derive instance Generic AddressKindValues _
instance IsCslEnum AddressKindValues AddressKind
instance Show AddressKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- PlutusDatumSchema

foreign import data PlutusDatumSchema :: Type

data PlutusDatumSchemaValues
  = PlutusDatumSchema_BasicConversions
  | PlutusDatumSchema_DetailedSchema

derive instance Generic PlutusDatumSchemaValues _
instance IsCslEnum PlutusDatumSchemaValues PlutusDatumSchema
instance Show PlutusDatumSchemaValues where
  show = genericShow

--------------------------------------------------------------------------------
-- CredKind

foreign import data CredKind :: Type

data CredKindValues
  = CredKind_Key
  | CredKind_Script

derive instance Generic CredKindValues _
instance IsCslEnum CredKindValues CredKind
instance Show CredKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- MIRKind

foreign import data MIRKind :: Type

data MIRKindValues
  = MIRKind_ToOtherPot
  | MIRKind_ToStakeCredentials

derive instance Generic MIRKindValues _
instance IsCslEnum MIRKindValues MIRKind
instance Show MIRKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- NetworkIdKind

foreign import data NetworkIdKind :: Type

data NetworkIdKindValues
  = NetworkIdKind_Testnet
  | NetworkIdKind_Mainnet

derive instance Generic NetworkIdKindValues _
instance IsCslEnum NetworkIdKindValues NetworkIdKind
instance Show NetworkIdKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- CborContainerType

foreign import data CborContainerType :: Type

data CborContainerTypeValues
  = CborContainerType_Array
  | CborContainerType_Map

derive instance Generic CborContainerTypeValues _
instance IsCslEnum CborContainerTypeValues CborContainerType
instance Show CborContainerTypeValues where
  show = genericShow

--------------------------------------------------------------------------------
-- MIRPot

foreign import data MIRPot :: Type

data MIRPotValues
  = MIRPot_Reserves
  | MIRPot_Treasury

derive instance Generic MIRPotValues _
instance IsCslEnum MIRPotValues MIRPot
instance Show MIRPotValues where
  show = genericShow

--------------------------------------------------------------------------------
-- ScriptHashNamespace

foreign import data ScriptHashNamespace :: Type

data ScriptHashNamespaceValues
  = ScriptHashNamespace_NativeScript
  | ScriptHashNamespace_PlutusScript
  | ScriptHashNamespace_PlutusScriptV2
  | ScriptHashNamespace_PlutusScriptV3

derive instance Generic ScriptHashNamespaceValues _
instance IsCslEnum ScriptHashNamespaceValues ScriptHashNamespace
instance Show ScriptHashNamespaceValues where
  show = genericShow

--------------------------------------------------------------------------------
-- LanguageKind

foreign import data LanguageKind :: Type

data LanguageKindValues
  = LanguageKind_PlutusV1
  | LanguageKind_PlutusV2
  | LanguageKind_PlutusV3

derive instance Generic LanguageKindValues _
instance IsCslEnum LanguageKindValues LanguageKind
instance Show LanguageKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- NativeScriptKind

foreign import data NativeScriptKind :: Type

data NativeScriptKindValues
  = NativeScriptKind_ScriptPubkey
  | NativeScriptKind_ScriptAll
  | NativeScriptKind_ScriptAny
  | NativeScriptKind_ScriptNOfK
  | NativeScriptKind_TimelockStart
  | NativeScriptKind_TimelockExpiry

derive instance Generic NativeScriptKindValues _
instance IsCslEnum NativeScriptKindValues NativeScriptKind
instance Show NativeScriptKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- TransactionMetadatumKind

foreign import data TransactionMetadatumKind :: Type

data TransactionMetadatumKindValues
  = TransactionMetadatumKind_MetadataMap
  | TransactionMetadatumKind_MetadataList
  | TransactionMetadatumKind_Int
  | TransactionMetadatumKind_Bytes
  | TransactionMetadatumKind_Text

derive instance Generic TransactionMetadatumKindValues _
instance IsCslEnum TransactionMetadatumKindValues TransactionMetadatumKind
instance Show TransactionMetadatumKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- PlutusDataKind

foreign import data PlutusDataKind :: Type

data PlutusDataKindValues
  = PlutusDataKind_ConstrPlutusData
  | PlutusDataKind_Map
  | PlutusDataKind_List
  | PlutusDataKind_Integer
  | PlutusDataKind_Bytes

derive instance Generic PlutusDataKindValues _
instance IsCslEnum PlutusDataKindValues PlutusDataKind
instance Show PlutusDataKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- CertificateKind

foreign import data CertificateKind :: Type

data CertificateKindValues
  = CertificateKind_StakeRegistration
  | CertificateKind_StakeDeregistration
  | CertificateKind_StakeDelegation
  | CertificateKind_PoolRegistration
  | CertificateKind_PoolRetirement
  | CertificateKind_GenesisKeyDelegation
  | CertificateKind_MoveInstantaneousRewardsCert
  | CertificateKind_CommitteeHotAuth
  | CertificateKind_CommitteeColdResign
  | CertificateKind_DrepDeregistration
  | CertificateKind_DrepRegistration
  | CertificateKind_DrepUpdate
  | CertificateKind_StakeAndVoteDelegation
  | CertificateKind_StakeRegistrationAndDelegation
  | CertificateKind_StakeVoteRegistrationAndDelegation
  | CertificateKind_VoteDelegation
  | CertificateKind_VoteRegistrationAndDelegation

derive instance Generic CertificateKindValues _
instance IsCslEnum CertificateKindValues CertificateKind
instance Show CertificateKindValues where
  show = genericShow

--------------------------------------------------------------------------------
-- MetadataJsonSchema

foreign import data MetadataJsonSchema :: Type

data MetadataJsonSchemaValues
  = MetadataJsonSchema_NoConversions
  | MetadataJsonSchema_BasicConversions
  | MetadataJsonSchema_DetailedSchema

derive instance Generic MetadataJsonSchemaValues _
instance IsCslEnum MetadataJsonSchemaValues MetadataJsonSchema
instance Show MetadataJsonSchemaValues where
  show = genericShow

--------------------------------------------------------------------------------
-- DRepKind

foreign import data DRepKind :: Type

data DRepKindValues
  = DRepKind_KeyHash
  | DRepKind_ScriptHash
  | DRepKind_AlwaysAbstain
  | DRepKind_AlwaysNoConfidence

derive instance Generic DRepKindValues _
instance IsCslEnum DRepKindValues DRepKind
instance Show DRepKindValues where
  show = genericShow

