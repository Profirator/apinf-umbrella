# Testing

## Test Suite

API Umbrella's test suite uses Ruby's [minitest](https://github.com/seattlerb/minitest). All tests are located in the
[`test`](https://github.com/FIWARE/api-umbrella/tree/master/test) directory. Tests are separated into these areas:

-   [`test/admin_ui`](https://github.com/FIWARE/api-umbrella/tree/master/test/admin_ui): Browser-based tests for the
    `admin-ui` component using [Capybara](http://teamcapybara.github.io/capybara/).
-   [`test/apis`](https://github.com/FIWARE/api-umbrella/tree/master/test/apis): HTTP tests for the internal APIs
    provided by API Umbrella.
-   [`test/processes`](https://github.com/FIWARE/api-umbrella/tree/master/test/processes): Testing the behavior of API
    Umbrella's server processes.
-   [`test/proxy`](https://github.com/FIWARE/api-umbrella/tree/master/test/proxy): Testing the behavior of API
    Umbrella's proxy features.
-   [`test/testing_sanity_checks`](https://github.com/FIWARE/api-umbrella/tree/master/test/testing_sanity_checks): Tests
    to sanity check certain behaviors of the overall test suite.

## Running Tests

For running the tests, the ```Dockerfile-test``` can be used. After building the base-image, the test image can be build:

```
    docker build -f Dockerfile-test --build-arg BASE_IMAGE=<IMAGE_TO_TEST> -t umbrella-test . 
```

Before executing the actual tests, the environment([MongoDB](https://www.mongodb.com/) and [Elasticsearch](https://www.elastic.co/)) needs to be 
provided. 

```
    docker-compose -f docker/compose/docker-compose.yaml up
```

Test can then be executed via:

```
    docker run --network host  -v $(pwd)/pics:/app/test/tmp/capybara umbrella-test make test
```

All screenshots taken by selenium/capybara can be found at $(pwd)/pics after that. To access logfiles of all umbrella components, the tests should
be executed as following:

```
    docker run --network host  -v $(pwd)/pics:/app/test/tmp/capybara --entrypoint bash -it umbrella-test
    make test
``` 

Logs can be found at `/app/test/tmp/run/api-umbrella-root/var/log`

### Running Individual Tests

Individual tests can be run in a similar way. Precondition is a running enviornment, as described in the previous paragraph.
The test to run can be provided via the environment variable `TEST_TO_RUN` and can either be a single test file(f.e. `test/apis/admin/stats/test_logs.rb`) 
or a folder to run all test below that(f.e. `test/apis/admin/stats`).

```
    docker run -e TEST_TO_RUN=<MY_TEST> --network host  -v $(pwd)/pics:/app/test/tmp/capybara --entrypoint bash -it umbrella-test
    make single-test
``` 
