# Exploring Rego, Open Policy Agent's policy language

### Gatekeeper

#### Note: In order to enforce policies on "DELETE" operations you will need to edit the ValidatingWebhookConfiguration spec to include this operation.

The folder above for Gatekeeper will be used to provide example rules (outside of those that already exist in the Gatekeeper project repository). I will also be using this folder for testing out the new policy tool "konstraint" by jpreese :) (when I've got some time to be thorough!).

### Kube-mgmt

#### Subtle differences to the Gatekeeper project

This folder is used to keep examples for where I have used kube-mgmt instead of Gatekeeper, these policies are loaded through ConfigMaps and not into CRDs like the Constraint Templates and Constraints.

### Other policies not related to k8s

#### Terraform and other examples
