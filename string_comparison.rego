package functions

trim_and_split(s) = result {
     t := trim(s, " ")
     result := split(t, ".")
}

hello[x] {
x := trim_and_split("  hello.world.john.smith  ")
}

help[{"value": f, "index": z}]{
 some y, z
 hello[y]
 y[z] == str[_]
 f := y[z]
}

str = ["world", "smith"]
