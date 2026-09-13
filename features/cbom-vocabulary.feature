Feature: A CBOM a stranger can validate

  The README promises a CycloneDX 1.6 CBOM. A document that carries the spec's
  version and not its vocabulary is a claim a consumer acts on and is wrong
  about: an ingestion pipeline validating strictly rejects it, and the
  operator learns that from the pipeline, not from qryx.

  @decided 2026-09-13: every value written into one of the spec's closed enums
  passes through one mapping at the boundary, decided by primitive and
  algorithm name, and the whole internal vocabulary is walked through it in a
  test against the enums copied from the schema. Found by POL-5 of the 1.0
  proving run: the image CBOM of a real gateway image failed validation nine
  times while the source CBOM passed.

  Background:
    Given qryx has scanned a target and built its asset graph

  # @test:TestCBOMStaysInsideCycloneDX16Vocabulary
  Scenario: Every value in the document is one the schema names
    When the operator asks for the CBOM
    Then every primitive, asset type, protocol type and component type is in the CycloneDX 1.6 enum
    And a protocol asset carries protocol properties, not algorithm properties
    And a key carries related-crypto-material properties
    And a library is a library component with no crypto properties

  # @test:TestCBOMPrimitiveMappingIsSpecific
  Scenario: The mapping says what the algorithm is, not "other" for everything
    When an internal "encryption" finding names AES, RC4 or RSA
    Then the CBOM says block-cipher, stream-cipher or pke respectively
    And a "key-exchange" finding is key-agree, or kem for ML-KEM
    And a "hash" finding named HMAC is a mac
