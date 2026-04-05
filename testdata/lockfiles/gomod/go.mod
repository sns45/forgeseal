module example.com/myproject

go 1.22

require (
	github.com/gorilla/mux v1.8.1
	github.com/spf13/cobra v1.8.0
	github.com/stretchr/testify v1.9.0
	golang.org/x/sys v0.29.0
	github.com/go-chi/chi/v5 v5.0.12
)

require (
	github.com/davecgh/go-spew v1.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace golang.org/x/sys v0.29.0 => golang.org/x/sys v0.30.0
