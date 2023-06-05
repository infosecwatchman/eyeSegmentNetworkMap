# Overview

This project is an extension of the Forescout (<https://forescout.com>) eyeSegment product. Information about eyeSegment can be found on here: <https://www.forescout.com/resources/forescout-eyesegment-datasheet/>. 

This project is a GoLang project to dynamically filter and display connection data pulled from eyeSegment.

Go 1.19 was used to build this project.

## Getting Started

- To get started you can either download from the releases page, and run `eyeSegmentNetworkMap.exe -h` to view the syntax, or clone and build the project yourself.

### Basic Syntax

- Start the server:
```eyeSegmentNetworkMap -t appliance.forescout.local```

## Building from source
> These steps assume you already have Go installed, if not please visit <https://golang.org/dl/> to download and install the latest version to your computer.

1. ```git clone github.com/infosecwatchman/eyeSegmentNetworkMap```
2. ```cd ./eyeSegmentNetworkMap/v1```
3. ```go build .```