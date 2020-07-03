package test

make_review(obj) = res {
	res := input.request.name
}

hello[review_obj] {
	review_obj := make_review(input)
}

goodbye[container_obj] {
	container_obj := make_container(input_container)
}

make_container(obj) = c {
	c := input_container[x]
}

input_container[x] {
	x := container[_]
}

container = {"name": ["busybox", "nginx"]}
