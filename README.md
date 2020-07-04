# Exploring Rego, Open Policy Agent's policy language

### Gatekeeper

#### Note: In order to enforce policies on "DELETE" operations you will need to edit the ValidatingWebhookConfiguration spec to include this operation.

The folder above for Gatekeeper will be used to provide example rules (outside of those that already exist in the Gatekeeper project repository). I will also be using this folder for testing out the new policy tool "konstraint" by jpreese :) (when I've got some time to be thorough!).

### Kube-mgmt

#### Subtle differences to the Gatekeeper project

This folder is used to keep examples for where I have used kube-mgmt instead of Gatekeeper, these policies are loaded through ConfigMaps and not into CRDs like the Constraint Templates and Constraints.

Tips:
  - Beware of creating ConfigMaps in namespaces where you do not have the label `openpolicyagent.org/policy=rego` or `openpolicyagent.org/webhook=ignore`
  - When you replicate data from within the spec of the kube-mgmt container, this overides the label above
  - Verify the data structure of the replicated data using the following from a node (I'm using kind so `docker ps | grep 'control'`;
  `curl -sk https://OPA_SVC_IP/v1/data/kubernetes/<object>` to check it exists, then output that to a file with `| jq .result > <filename>.json` to trim the result off which is part of the REST API's response, `tar cf <filename>.json dir` then `docker cp <container>:<dir> <local_location/name>`, finally `tar cf <local file>` and you can use the normal OPA REPL interface to do some testing `opa run /path/to/test/data`
  - One that gave me a particularly hard time, but perservered and the result is [here](https://play.openpolicyagent.org/p/pcXTjTIni4)
  - The link to the Playground in the above point also has the unit testing data within
  - Testing is not as easy as it could be, after unit testing you might want to just run a sidecar container with OPA, configmap in an isolated policy for testing, and go from there - I may explore this in a blog post
  
  
  
  

### Other policies not related to k8s

#### Terraform and other examples
