BIN = pki

all: build

build: FORCE
	go build -o $(BIN) .

check: vet

vet:
	go vet $(CURDIR)/...

clean:
	$(RM) $(BIN)

FORCE:

.PHONY: all build check vet clean
