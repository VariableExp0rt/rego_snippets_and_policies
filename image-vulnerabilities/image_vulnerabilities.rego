package kubernetes.admission

#import data.kubernetes.vulnerabilities

default allow = false

violation[{"msg": msg}] {
    msg := get_unsafe_images(image_match, crit_count_by_image)
}

violation[{"msg": msg}] {
	count(image_match) > 0
    msg := get_unsafe_images(image_match, crit_count_by_image)
}

allow {
	get_safe_images(image_match, crit_count_by_image) 
}

get_unsafe_images(image_match, crit_count_by_image) = msg { 
    input_container[i]
    count(image_match) == 0
    msg := sprintf("Container %v forbidden, no image scan records found", [i])
}

get_unsafe_images(image_match, crit_count_by_image) = msg { 
    image_match[d]
    crit_count_by_image[i]
    d == i
    crit_count_by_image[i] > 0
    msg := sprintf("Container %v forbidden, critical vulnerabilities identified in image", [i])
}

get_safe_images(image_match, crit_count_by_image) = msg { 
    image_match[d]
    crit_count_by_image[i]
    d == i
    crit_count_by_image[i] < 1
    msg := sprintf("Container %v allowed, no critical vulnerabilities identified in image", [i])
}

##Helper rules are below
input_container[c] {
	#Will be changed input.request.object.spec.containers[_]
	c := {"busybox"}
}

##Should be rule to extract the necessary fields from data.kubernetes.vulnerabilities
vulnerabilities := input

##New rule to match images to their respective criticalCount
crit_count_by_image[image] = cCount {
    item := input.items[_].items[_]
    image := item.metadata.labels["starboard.container.name"]
    cCount := item.report.summary["criticalCount"]
}

##Find matches to images in the vulnerability reports with the requested image
image_match[a] {
    item := input.items[_].items[_]
    a := item.metadata.labels["starboard.container.name"]
    input_container[c]
    c[a]
}

