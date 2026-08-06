// An Azure Key Vault symmetric key. `oct` and `oct-HSM` are the only Key Vault
// key types whose length is not derivable from public metadata, and Key Vault
// and Managed HSM both accept 128, 192 and 256-bit oct keys, so the size qryx
// reports for this resource is genuinely unknown rather than merely absent.
resource "azurerm_key_vault_key" "symmetric" {
  name     = "app-data-key"
  key_type = "oct"
}
