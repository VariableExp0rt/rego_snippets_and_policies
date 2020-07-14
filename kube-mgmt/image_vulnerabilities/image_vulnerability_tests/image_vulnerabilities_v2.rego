package kubernetes.admission

##PATH
## vulnerabilities.<namespace>.<resource_id>.metadata.labels["starboard.container.name"]
## vulnerabilities.<namespace>.<resource_id>.report.summary["criticalCount"]
import data.kubernetes.vulnerabilities

default allow = false

##DENY
deny[{"msg": msg}] {
	msg := get_type_result(image_match, crit_count_by_image)
}

##ALLOW
allow {
	count(image_match) > 0
    get_vulnerabilities(crit_count_by_image) = "0"
}

##FUNCTIONS
get_type_result(image_match, crit_count_by_image) = msg {
	count(image_match) == 0
    msg := sprintf("Image %v has not been scanned, cannot deploy", [image_match.a])
}

get_type_result(image_match, crit_count_by_image) = msg {
	count(image_match) > 0
    get_vulnerabilities(crit_count_by_image) == "1"
    msg := sprintf("%v critical vulnerabilities found in image: %v", [crit_count_by_image.cCount, image_match.a])
}

get_vulnerabilities(crit_count_by_image) = "1" {
	vulns := crit_count_by_image[image]
    vulns > 0
}

get_vulnerabilities(crit_count_by_image) = "0" {
	vulns := crit_count_by_image[image]
    vulns == 0
}

###RULES
crit_count_by_image[image] = cCount {
    item := input[_][_]
    image := item.name
    cCount := item.report.summary["criticalCount"]
}

image_match[a] {
    item := vulnerabilities[_][_]
    a := item.metadata.labels["starboard.container.name"]
    input_image[img]
    img[a]
}

input_image[img] {
	img := input.request.object.spec.containers[_].image
}

input_image[img] {
	img := input.request.object.spec.template.spec.containers[_].image
}

