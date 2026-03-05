FROM registry.redhat.io/ubi9/ubi-minimal:latest

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN make

FROM registry.ci.openshift.org/ocp/4.21:base-rhel9

ARG OC_VERSION=latest
ARG TARGETARCH

RUN dnf -y update && \
    dnf install -y binutils file go podman runc jq skopeo nmap tar lsof && \
    dnf clean all

RUN wget -O "openshift-client-linux-${OC_VERSION}.tar.gz" "https://mirror.openshift.com/pub/openshift-v4/${TARGETARCH}/clients/ocp/${OC_VERSION}/openshift-client-linux.tar.gz" && \
    tar -C /usr/local/bin -xzvf "openshift-client-linux-$OC_VERSION.tar.gz" oc && \
    rm -f "openshift-client-linux-$OC_VERSION.tar.gz"

COPY --from=builder /app/bin/tls-scanner /usr/local/bin/tls-scanner

ENTRYPOINT ["/usr/local/bin/tls-scanner"]

LABEL com.redhat.component="tls-scanner"
