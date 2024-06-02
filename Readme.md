## Compile protobuf

You need to recompile your protobuf file if changes made in .proto file.

> protoc --proto_path=./proto --go_out=./src zk_auth.proto

## Build Docker

> docker-compose build zkpserver

## Run Docker & server

> docker-compose run --rm zkpserver
> root@e845234564349a:/zkp-server# cargo run --bin server --release

## List Docker

> docker container ls

CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
e4505045c5b6 zkp-chaum-pederson-zkpserver "bash" 7 minutes ago Up 7 minutes zkp-chaum-pederson-zkpserver-run-d6b7588581ff

## Run Client in the same container

e4505045c5b6 is the unique identifier of the docker running the server binary. We want to open a shell there and run our client together.

### Open the bash

> docker exec -it e4505045c5b6 /bin/bash

### Run the client

> root@e4505045c5b6:/zkp-server# cargo run --bin client --release
