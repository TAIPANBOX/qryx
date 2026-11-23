Feature: The NCSC 2031 migrated count is measured, or it says it was not

  The NCSC report's 2031 milestone counts the highest-priority assets that were
  migrated. A single scan cannot see what used to be there, so until this
  change the count was the literal 0 on every run, and a team that had replaced
  every exposed key read the same figure as a team that had done nothing.

  @decided 2026-11-23: the migrated count is measured from the --baseline
  snapshot the drift gate already reads. An asset counts as migrated when it was
  highest-priority in a baseline of the same target and is no longer in the
  asset graph at all. Assets are matched by the drift diff's identity (type,
  algorithm, key size, risk class), never by location. Without a like-for-like
  baseline the count is explicitly not measured: null in the JSON, the words
  "not measured" on the page, and a sentence saying why. It is never a 0.

  # @test:TestNCSCMigratedCountsAHighestPriorityAssetGoneSinceTheBaseline
  Scenario: A highest-priority asset in the baseline is gone now
    Given a baseline of a tree whose code agrees keys with ECDH
    When the key exchange is removed and the tree is scanned with that baseline
    Then the report says one asset was migrated and names it
    And nothing highest-priority remains

  # @test:TestNCSCMigratedDoesNotCountANewAsset
  Scenario: An asset that arrived after the baseline is not migrated
    Given a baseline of a tree with no cryptography
    When a key exchange is added
    Then the migrated count is a measured zero
    And the new asset is counted as remaining

  # @test:TestNCSCMigratedDoesNotCountAnAssetThatOnlyMovedFiles
  Scenario: An asset that only moved to another file is not migrated
    Given a baseline of a tree with a key exchange in one file
    When the same key exchange moves to another file
    Then the migrated count is a measured zero
    And the asset is still counted as remaining

  # @test:TestMeasureMigratedCountsOnlyAssetsGoneFromTheGraph
  Scenario: An asset still in the estate is not migrated even if it left the priority subset
    Given a baseline where RSA was seen on a live TLS endpoint
    When RSA is now seen only in code
    Then RSA is not counted as migrated, because the algorithm is still there

  # @test:TestNCSCMigratedIsNotMeasuredWithoutABaseline
  # @test:TestNCSCHTMLSaysMigratedIsNotMeasuredWithoutABaseline
  Scenario: No baseline means not measured, never zero
    When the tree is scanned with no --baseline
    Then the JSON carries a null migrated count and says it was not measured
    And the page says "migrated: not measured" rather than "0 migrated"

  # @test:TestNCSCMigratedIsNotMeasuredWhenTheBaselineIsMissing
  Scenario: A baseline that is not there is not measured against
    When --baseline names a file that does not exist
    Then the migrated count is not measured and the reason says it was not found

  # @test:TestNCSCMigratedFromAnEmptyBaselineIsAMeasuredZero
  Scenario: An empty baseline of the same target gives an earned zero
    Given a baseline of the same target with no assets in it
    Then the migrated count is a measured zero

  # @test:TestNCSCMigratedIsNotMeasuredAgainstABaselineOfAnotherTarget
  Scenario: A baseline of another target is refused
    Given a baseline of a different tree
    Then the migrated count is not measured, because a difference in what was scanned is not a migration

  # @test:TestNCSCMigratedRefusesAHostileBaseline
  Scenario: A hostile or malformed baseline file
    Given a baseline that is truncated, not an object, or binary
    Then the scan stops with an error naming the baseline
    And a baseline of another schema version is not measured against
    And one asset listed twice counts once

  # @test:TestNCSCHTMLShowsTheMeasuredMigratedCount
  Scenario: The page shows a measured count
    Given a baseline with one highest-priority asset that is gone now
    Then the page says "1 migrated since the baseline"
