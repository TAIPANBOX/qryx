Feature: Where does my own code reach an AI model

  The question behind this is one an operator has to answer about their own
  estate, and until now qryx could answer it only on a terminal. The findings
  were there, accurate, and had no door out of the tool that another program
  could walk through.

  Background:
    Given a source tree the operator owns
    And qryx has scanned it

  # @test:TestAIInventoryCarriesProviderAndRole
  Scenario: An answer another program can read
    When the operator asks for the inventory in a machine format
    Then each row names the provider by a stable id, not by a sentence
    And it says whether that id came from an SDK, a framework, or a local runtime
    And it names every file and line the evidence came from

  # @test:TestAIUsageCarriesACanonicalProvider
  Scenario: One vocabulary, owned in one place
    Given the same provider can be found in a manifest, an import, or a bare endpoint
    When any of the three is found
    Then all three report the same provider id
    And that id comes from the detector's own tables rather than being guessed downstream

  # @test:TestAIUsageFrameworkNamesNoProvider
  Scenario: Code that reaches a model through an indirection
    Given the tree calls a model through LangChain or LiteLLM
    When the inventory is written
    Then the row is present, because the tree does reach a model
    And its provider is left open, because which one is chosen by configuration this scan cannot read

  # @test:TestAIInventoryAlwaysStatesItsLimits
  Scenario: An empty answer is not an all-clear
    Given a tree where the scan finds nothing
    When the inventory is written
    Then the document still states what this scan cannot see
    And it says in words that an empty result is not proof that the tree uses no AI

  # @test:TestAIInventoryExcludesCryptographicAssets
  Scenario: The AI inventory holds only AI facts
    Given the same scan also found cryptographic assets
    When the AI inventory is written
    Then no cryptographic asset appears in it

  # @test:TestAIInventoryIsDeterministic
  Scenario: Two scans of one unchanged tree produce one document
    When the operator scans the same tree twice
    Then the two documents are identical apart from the time they were generated
    And a diff between two dates shows a real change or nothing at all

  # @test:TestAIUsageManifestNeedleIsAWholeToken
  Scenario: A provider is never invented out of an English word
    Given a manifest whose description says "a raft-replicated ledger"
    When the inventory is written
    Then no provider named Replicate appears
    And nothing else in the estate's manifests names a provider its code never calls

  # @test:TestAIUsageManifestStillMatchesRealPackageNames
  Scenario: Real dependency lines are still recognised
    Given the manifest lines real ecosystems actually write
    When the inventory is written
    Then each one still names its provider

  # @test:TestAIUsageAzureOpenAIIsNotOpenAI
  Scenario: The same model, but the bytes leave for a different company
    Given the tree depends on "@azure/openai"
    When the operator asks who this code talks to
    Then the answer is Azure OpenAI
    And nothing in the inventory says this tree calls OpenAI, because it never has

  # @test:TestAIUsageManifestSpecificityKeepsBothRealDependencies
  Scenario: A tree that really uses both is still reported as both
    Given the same manifest depends on "openai" and on "@azure/openai"
    When the operator asks who this code talks to
    Then both providers are named
    And it does not matter which of the two the manifest lists first

  # @test:TestAIUsagePythonAzureOpenAIImportNamesAzureOnly
  Scenario: Azure code written the way Azure code is actually written
    Given the tree imports AzureOpenAI from the openai package
    When the operator asks who this code talks to
    Then the answer is Azure OpenAI alone, because that is where the request goes

  # @test:TestAIUsageEndpointLiteralNamesExactlyOneProvider
  Scenario: One address, one answer
    Given a config file naming a provider endpoint and nothing else
    When the inventory is written
    Then exactly one provider is named for that address
    And a Vertex AI host is not filed under the Gemini API, nor an Azure host under OpenAI

  # @test:TestAIUsagePythonDottedModuleImports
  Scenario: A rule that quietly stopped asking its question
    Given python code that imports a provider SDK by a dotted module path
    When the inventory is written
    Then the provider is named
    And the check that was meant to catch this can be shown failing without it
