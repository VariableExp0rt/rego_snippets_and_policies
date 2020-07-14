package kubernetes.admission

##PATH
## vulnerabilities.<namespace>.<resource_id>.metadata.labels["starboard.container.name"]
## vulnerabilities.<namespace>.<resource_id>.report.summary["criticalCount"]
#import data.kubernetes.vulnerabilities

default allow = false

##DENY
deny[{"msg": msg}] {
	msg := get_type_result(crit_count_by_image)
}

##ALLOW
allow {
	count(image_match) > 0
    get_vulnerabilities(crit_count_by_image) = "0"
}

##FUNCTIONS
get_type_result(crit_count_by_image) = msg {
	count(image_match) == 0
    msg := sprintf("No vulnerability reports for image %v found, cannot deploy", [input_image])
}

get_type_result(crit_count_by_image) = msg {
	count(image_match) > 0
    get_vulnerabilities(crit_count_by_image) == "1"
    crits := crit_count_by_image[_]
    msg := sprintf("%v critical vulnerabilities found in image: %v", [crits, image_match])
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

vulnerabilities = {"dev": {"resource": {"metadata": {"labels": {"starboard.container.name": "nginx"}}, "report": {"summary": {"criticalCount": 1}}}}}



