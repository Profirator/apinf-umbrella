# Building Docker Images

## Prerequisites

<span/>

-   git
-   Docker

## Building Images

The build is split into a base-image, that is used as the build-stage and the concrete image built of the base. 

To build the base image for the current API Umbrella version:

```
docker build -f Dockerfile-base -t fiware/api-umbrella-base:INSERT_VERSION_HERE .
```

To build the executable image of the previous base image, use the `Dockerfile-build-from-base`. The base image can be provided as a build argument. It defaults to the latest base image.

```
docker build -f Dockerfile-build-from-base -t fiware/api-umbrella:INSERT_VERSION_HERE --build-arg BASE_IMAGE=fiware/api-umbrella-base:INSERT_VERSION_HERE .
```

> :warning: The dockerfiles `Dockerfile-beta-deploy`, `Dockerfile-build`, `Dockerfile-dev` and `Dockerfile-dev-build` are deprecated and will be
> removed in the future.
