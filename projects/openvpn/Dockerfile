# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y pkg-config make autoconf automake libtool libssl-dev liblzo2-dev libpam-dev libnl-3-dev libnl-genl-3-dev libcap-ng-dev

RUN git clone --depth 1 https://github.com/google/boringssl.git boringssl
RUN git clone --depth 1 https://github.com/R9295/openvpn openvpn
WORKDIR openvpn
RUN cp ./fuzz/fuzz_header.h ./src/openvpn/
RUN ./fuzz/build.sh
