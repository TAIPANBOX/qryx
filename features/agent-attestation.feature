Feature: An agent's declared attestation is never reported as verified

  An Agent Passport names an attestation method in its own JSON. qryx cannot
  check the mechanism behind that name, so its findings must say the method is
  declared, and an evidence check run in CI must not pass unless the caller
  named the signer.

  @decided 2026-10-17: a passport's attestation method is reported as declared,
  never as verified. In CI mode an evidence check refuses to pass without a
  pinned signer. Outside CI mode an unpinned check is reported as not verified,
  never as a pass. Found by finding F-020 of the 2026-10-17 security review,
  where a re-signed evidence document passed because no signer was pinned.

  Background:
    Given qryx has read an Agent Passport and a signed evidence document

  # @test:TestPassportAttestationIsDeclaredNotVerified
  Scenario: A passport's attestation method is reported as declared
    When qryx reports the attestation of the agent
    Then the finding says the method is declared
    And the finding does not say that an attestation took place
    And the finding says the declaration is not verified

  # @test:TestVerifyEvidenceCIModeRefusesWithoutAPin
  Scenario: CI mode refuses an evidence check with no signer pinned
    When the operator runs verify-evidence in CI mode without a signer
    Then the check refuses and says that no signer is pinned
    And the check prints no verdict

  # @test:TestVerifyEvidenceUnpinnedIsNotVerified
  Scenario: Outside CI mode an unpinned check is reported as not verified
    When the operator runs verify-evidence without a signer and without CI mode
    Then the output says "not verified: no signer pinned"
    And the output never says VERIFIED
    And the output names the key the operator would pin

  # @test:TestVerifyEvidenceCIModeAcceptsThePinnedSigner
  Scenario: CI mode passes only the signer the caller named
    When the operator runs verify-evidence in CI mode with the real signer pinned
    Then the output says VERIFIED

  # @test:TestVerifyEvidenceCIRejectsAForgeryResignedByAnotherKey
  Scenario: A document re-signed by another key does not pass CI
    Given a document was rewritten and signed again by a different key
    When the operator runs verify-evidence in CI mode
    Then the check refuses, whether or not the real signer is named

  # @test:TestVerifyEvidenceWrongPinFailsInEveryMode
  Scenario: A signer pin that names a different key fails in every mode
    When the operator pins a key that did not sign the document
    Then the check refuses, with CI mode on or off
