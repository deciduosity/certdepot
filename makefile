buildDir := build
name := certdepot
packages := certdepot
projectPath := github.com/evergreen-ci/certdepot
#
# override the go binary path if set
gobin := $(GO_BIN_PATH)
ifeq (,$(gobin))
gobin := go
endif
gopath := $(GOPATH)
gocache := $(abspath $(buildDir)/.cache)
ifeq ($(OS),Windows_NT)
ifneq (,$(gopath))
gopath := $(shell cygpath -m $(gopath))
endif
gocache := $(shell cygpath -m $(gocache))
endif
goEnv := GOPATH=$(gopath) GOCACHE=$(gocache)$(if $(GO_BIN_PATH), PATH="$(shell dirname $(GO_BIN_PATH)):$(PATH)")


# start lint setup targets
lintDeps := $(buildDir)/.lintSetup $(buildDir)/run-linter $(buildDir)/golangci-lint
$(buildDir)/.lintSetup:$(buildDir)/golangci-lint
	@touch $@
$(buildDir)/golangci-lint:$(buildDir)
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/76a82c6ed19784036bbf2d4c84d0228ca12381a4/install.sh | sh -s -- -b $(buildDir) v1.23.8 >/dev/null 2>&1
$(buildDir)/run-linter:cmd/run-linter/run-linter.go $(buildDir)/.lintSetup $(buildDir)
	@$(goEnv) $(gobin) build -o $@ $<
# end lint setup targets


testArgs := -v
ifneq (,$(RUN_TEST))
testArgs += -run='$(RUN_TEST)'
endif
ifneq (,$(RUN_COUNT))
testArgs += -count='$(RUN_COUNT)'
endif
ifneq (,$(SKIP_LONG))
testArgs += -short
endif
ifeq (,$(DISABLE_COVERAGE))
testArgs += -cover
endif
ifneq (,$(RACE_DETECTOR))
testArgs += -race
endif
# test execution and output handlers
$(buildDir)/output.%.test:$(buildDir)/ .FORCE
	$(goEnv) $(gobin) test $(testArgs) ./$(if $(subst $(name),,$*),$*,) | tee $@
	@! grep -s -q -e "^FAIL" $@ && ! grep -s -q "^WARNING: DATA RACE" $@
$(buildDir)/output.test:$(buildDir)/ .FORCE
	$(goEnv) $(gobin) test $(testArgs) ./ | tee $@
	@! grep -s -q -e "^FAIL" $@ && ! grep -s -q "^WARNING: DATA RACE" $@
$(buildDir)/output.%.coverage:$(buildDir)/ .FORCE
	$(goEnv) $(gobin) test $(testArgs) ./$(if $(subst $(name),,$*),$*,) -covermode=count -coverprofile $@ | tee $(buildDir)/output.$*.test
	@-[ -f $@ ] && $(gobin) tool cover -func=$@ | sed 's%$(projectPath)/%%' | column -t
$(buildDir)/output.coverage:$(buildDir)/ .FORCE
	$(goEnv) $(gobin) test $(testArgs) -covermode=count -coverprofile $@ ./ | tee $(buildDir)/output.$*.test
$(buildDir)/output.%.coverage.html:$(buildDir)/output.%.coverage
	$(goEnv) $(gobin) tool cover -html=$< -o $@
$(buildDir)/output.coverage.html: $(buildDir)/output.coverage .FORCE
	$(goEnv) $(gobin) tool cover -html=$< -o $@
#  targets to generate gotest output from the linter.
$(buildDir)/output.%.lint:$(buildDir)/run-linter $(buildDir) .FORCE
	$(goEnv) ./$< --output=$@ --lintBin=$(buildDir)/golangci-lint --packages='$*'
$(buildDir)/output.lint:$(buildDir)/run-linter $(buildDir) .FORCE
	$(goEnv) ./$< --output=$@ --lintBin=$(buildDir)/golangci-lint --packages='$(packages)'
#  targets to process and generate coverage reports
# end test and coverage artifacts


# userfacing targets for basic build and development operations
compile:
	$(goEnv) $(gobin) build ./
test:$(buildDir)/output.test
coverage:$(buildDir)/output.coverage
	$(goEnv) $(gobin) tool cover -func=$< | sed -E 's%github.com/.*/certdepot/%%' | column -t
coverage-html:$(buildDir)/output.coverage.html

benchmark:
	$(goEnv) $(gobin) test -v -benchmem -bench=. -run="Benchmark.*" -timeout=20m
lint:$(foreach target,$(packages),$(buildDir)/output.$(target).lint)

phony += lint build race test coverage coverage-html
.PRECIOUS:$(foreach target,$(packages),$(buildDir)/output.$(target).lint)
.PRECIOUS:$(buildDir)/output.lint
# end front-ends


$(buildDir): compile
	@mkdir -p $@


vendor-clean:
	rm -rf vendor/github.com/mongodb/grip/vendor/github.com/stretchr/testify/
	rm -rf vendor/github.com/mongodb/grip/vendor/github.com/pkg/errors/
	rm -rf vendor/go.mongodb.org/mongo-driver/vendor/github.com/stretchr/testify/
	rm -rf vendor/go.mongodb.org/mongo-driver/vendor/github.com/pkg/errors/
	find vendor/ -type d -empty | xargs rm -rf
	find vendor/ -name "*.gif" -o -name "*.gz" -o -name "*.png" -o -name "*.ico" -o -name "*testdata*" | xargs rm -rf
phony += vendor-clean
clean:
	rm -rf $(lintDeps)
phony += clean

# mongodb utility targets
mongodb/.get-mongodb:
	rm -rf mongodb
	mkdir -p mongodb
	cd mongodb && curl "$(MONGODB_URL)" -o mongodb.tgz && $(DECOMPRESS) mongodb.tgz && chmod +x ./mongodb-*/bin/*
	cd mongodb && mv ./mongodb-*/bin/* . && rm -rf db_files && rm -rf db_logs && mkdir -p db_files && mkdir -p db_logs
get-mongodb: mongodb/.get-mongodb
	@touch $<
start-mongod: mongodb/.get-mongodb
	./mongodb/mongod --dbpath ./mongodb/db_files
	@echo "waiting for mongod to start up"
check-mongod: mongodb/.get-mongodb
	./mongodb/mongo --nodb --eval "assert.soon(function(x){try{var d = new Mongo(\"localhost:27017\"); return true}catch(e){return false}}, \"timed out connecting\")"
	@echo "mongod is up"
# end mongodb targets

# configure phony targets
.FORCE:
.PHONY:$(phony) .FORCE
