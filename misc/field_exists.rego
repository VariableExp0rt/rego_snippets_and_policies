package main

has_field(obj, field) {
    obj[field]
}

mytest[res] {
	obj := input_containers[c]
	res := has_field(obj, "name")
}

input_containers[c] {
	c := input.request.object.spec.containers[_]
}
