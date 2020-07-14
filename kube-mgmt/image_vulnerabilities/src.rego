package kubernetes.admission

##PATH
## vulnerabilities.<namespace>.<resource_id>.metadata.labels["starboard.container.name"]
## vulnerabilities.<namespace>.<resource_id>.report.summary["criticalCount"]
import data.kubernetes.vulnerabilities

default allow = false

##DENY
deny[msg] {
	msg := get_type_result(crit_count_by_image)
}

##ALLOW
allow {
	count(image_match) > 0
    get_vulnerabilities(crit_count_by_image) == "0"
}

##FUNCTIONS
get_type_result(crit_count_by_image) = msg {
	count(image_match) == 0
    imgs := {img | img := input_image[_]}
    msg := sprintf("No vulnerability reports for images in resource found, cannot deploy: %v", [imgs])
}

get_type_result(crit_count_by_image) = msg {
	count(image_match[m]) > 0
    get_vulnerabilities(crit_count_by_image) == "1"
    v := { v | v := crit_count_by_image[i] > 0}
    msg := sprintf("Critical vulnerabilities found in image: %v", [m])
}

get_vulnerabilities(crit_count_by_image) = "1" {
	vulns := crit_count_by_image[image]
    vulns > 0
}

get_vulnerabilities(crit_count_by_image) = "0" {
    vulns := { vulns | vulns := crit_count_by_image[_]}
    sum(vulns) < 1
}

###RULES
crit_count_by_image[image] = cCount {
    item := vulnerabilities[_][_]
    image := item.metadata.labels["starboard.container.name"]
    cCount := item.report.summary["criticalCount"]
}

image_match[a] {
    item := vulnerabilities[_][_]
    a := item.metadata.labels["starboard.container.name"]
    some i
    input_image[i] == a
}

input_image[img] {
    img := input.request.object.spec.containers[_].image
}

input_image[img] {
	img := input.request.object.spec.template.spec.containers[_].image
}
