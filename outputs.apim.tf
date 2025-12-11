output "apim" {
  description = "Resource outputs for apim"
  value       = var.apim_definition.deploy ? module.apim[0] : null
}
