FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN make

FROM registry.ci.openshift.org/ocp/4.21:base-rhel9

ARG OC_VERSION=latest
ARG UMOCI_VERSION=latest

RUN microdnf update -y && \
    microdnf install -y binutils file go podman runc jq skopeo nmap tar lsof && \
    microdnf clean all

RUN wget -O "openshift-client-linux-${OC_VERSION}.tar.gz" "https://mirror.openshift.com/pub/openshift-v4/amd64/clients/ocp/${OC_VERSION}/openshift-client-linux.tar.gz" && \
    tar -C /usr/local/bin -xzvf "openshift-client-linux-$OC_VERSION.tar.gz" oc && \
    rm -f "openshift-client-linux-$OC_VERSION.tar.gz"

RUN curl --fail --retry 3 -LJO https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest-4.14/opm-linux.tar.gz && \
    tar -xzf opm-linux.tar.gz && \
    mv ./opm /usr/local/bin/ && \
    rm -f opm-linux.tar.gz

RUN wget -O /usr/local/bin/umoci "https://github.com/opencontainers/umoci/releases/$UMOCI_VERSION/download/umoci.linux.amd64" && \
    chmod +x /usr/local/bin/umoci

COPY --from=builder /app/bin/tls-scanner /usr/local/bin/tls-scanner

ENTRYPOINT ["/usr/local/bin/tls-scanner"]

LABEL com.redhat.component="tls-scanner"
