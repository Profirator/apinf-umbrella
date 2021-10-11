#!/bin/bash

bundle exec puma  -q --dir /opt/api-umbrella/src -w $(yq e '.web.puma.workers' /config/config.yml) -t$(yq e '.web.puma.min_threads' /config/config.yml):$(yq e '.web.puma.max_threads' /config/config.yml)