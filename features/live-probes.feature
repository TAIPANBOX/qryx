Feature: What a live server will agree to, read from the wire

  A cryptographic inventory has to answer one question before any other on a
  live endpoint: is the session key agreed in a way a future quantum computer
  can recover from a recording made today? A certificate scan cannot answer it,
  because the certificate signs; it does not agree the key.

  @decided 2026-11-12: the live probes report the key exchange itself. The TLS
  probe reports the group the session was actually agreed with, named from its
  IANA code point. A new SSH probe reads what the server announces in its
  KEXINIT, which is the whole of what an SSH server tells a client before
  authentication, and reports whether a hybrid post-quantum exchange is among
  it. A classical exchange is quantum-vulnerable by the probe's own verdict,
  never by a classifier that does not know the name.

  # @test:TestEndpointReportsTheNegotiatedKeyExchangeGroup
  Scenario: A TLS server that takes the hybrid group is safe from harvest-now-decrypt-later
    Given a TLS 1.3 server
    When qryx probes it, offering X25519MLKEM768 first
    Then a server that accepts it is reported with that group and no risk
    And a server that agrees X25519 or P-256 alone is reported quantum-vulnerable

  # @test:TestKexGroupFinding
  Scenario: A group is named by its code point, not by the toolchain
    When the negotiated group is a hybrid this Go release has no name for
    Then it is still named and graded as a hybrid
    And every classical group carries its own quantum-vulnerable verdict and reason

  # @test:TestSSHFindingsPostQuantumKexOffered
  Scenario: An SSH server that offers a hybrid post-quantum exchange
    Given a server that lists mlkem768x25519-sha256 among its key exchanges
    When qryx reads its KEXINIT
    Then the key exchange is reported with no risk
    And the strict-kex and ext-info markers are not reported as algorithms
    And a stock OpenSSH 10 offer raises nothing

  # @test:TestSSHFindingsWithoutPostQuantumKexIsQuantumVulnerable
  Scenario: An SSH server with classical key exchange only
    Given a server whose key exchanges are curve25519, ECDH and Diffie-Hellman
    When qryx reads its KEXINIT
    Then the key exchange is reported quantum-vulnerable and high, naming the server's own first choice
    And the reason says no post-quantum exchange is offered

  # @test:TestSSHFindingsFlagWeakOfferedAlgorithms
  Scenario: Broken algorithms a server still offers are each named once
    Given a server that still offers SHA-1 Diffie-Hellman, ssh-rsa, DSA, 3DES, RC4, CBC modes and MD5
    When qryx reads its KEXINIT
    Then each is one finding with its own grade, even when offered in both directions
    And sound algorithms beside them raise nothing

  # @test:TestSSHHostKeysAreClassifiedCentrally
  Scenario: Host keys are graded by the same rules as every other key
    Given a server offering RSA, ECDSA P-384 and Ed25519 host keys, plus security-key and certificate variants
    When qryx reads its KEXINIT
    Then there is one finding per key family, graded by the central classifier
    And a host key type qryx does not know raises nothing

  # @test:TestSSHEndpointReadsALiveServer
  Scenario: The probe talks to a real socket
    Given a server that prints a line before its identification and sends an ignore message before KEXINIT
    When qryx connects
    Then it identifies itself as qryx, reports the server's banner as the SSH protocol asset and reads the key exchange

  # @test:TestSSHEndpointReportsProtocolOne
  Scenario: A server that speaks only SSH protocol 1
    When qryx connects
    Then it reports one critical misconfiguration and reads nothing further

  # @test:TestSSHProbeSurvivesHostileBytes
  Scenario: Every length and byte the server sends is hostile until checked
    Given a server that sends oversized, truncated, mis-padded or malformed data
    When qryx reads it
    Then each case ends in an error within the deadline, never a panic or a huge allocation
    And a well-formed server beside them still parses

  # @test:TestParseKexInitSurvivesRandomMutations
  Scenario: Two hundred seeded mutations of a real KEXINIT
    When the cookie alone is changed, the message still parses
    And whatever else is accepted is only lists of printable, non-empty names
