#!/bin/bash

GO=/usr/bin/go
SWIG=/usr/bin/swig
GOPATHDIR=gopath/src/goaiengine
echo "Compiling Go extension"
export CGO_CPPFLAGS="-I `pwd`" 
export CGO_CXXFLAGS="-DHAVE_CONFIG -DBINDING -DGO_BINDING -std=c++14"
export CGO_LDFLAGS="-lstdc++ -lboost_system -lboost_iostreams -lm -lpcap -lpcre";
export GOPATH=`pwd`/gopath
if [ ! -f goaiengine.a ]; then
    (cd $GOPATHDIR && go build -x -o goaiengine.a )
    cp $GOPATHDIR/goaiengine.a .
fi
$GO tool compile -pack -o goai.o goai.go
$GO tool link -linkmode external -extld "g++" -extldflags "-I/usr/include" -o goai_test goai.o
echo "Compilation sucess"
exit

