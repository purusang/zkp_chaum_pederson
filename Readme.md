## Compile protobuf

You need to recompile your protobuf file if changes made in .proto file.

> protoc --proto_path=./proto --go_out=./src zk_auth.proto
