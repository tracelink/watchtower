# Every stage is pinned to linux/amd64: the dev/prod nodes are amd64, while the Apple Silicon build machine
# would otherwise resolve a base image tag to whatever arm64 copy its local cache holds (deploy.sh also passes
# --platform linux/amd64). Base images move to our ECR later.
FROM --platform=linux/amd64 eclipse-temurin:21-jdk-jammy AS build
WORKDIR /workspace
COPY . .
RUN ./mvnw -B clean package -DskipTests \
      -Dmaven.javadoc.skip=true -Dmaven.source.skip=true

FROM --platform=linux/amd64 node:22.23.2-bookworm-slim AS node-runtime

# Betterleaks secrets scanner (MIT). Pinned and checksum-verified; the version must match
# BetterleaksModule.BETTERLEAKS_VERSION (enforced by BetterleaksPinnedVersionTest).
FROM --platform=linux/amd64 debian:bookworm-slim AS betterleaks
# amd64 only (see the FROM lines): not the predefined TARGETARCH, which follows the build command's platform.
ARG BUILD_ARCH=amd64
ARG BETTERLEAKS_VERSION=1.8.1
ARG BETTERLEAKS_SHA256_AMD64=efa407244e1ea8e35f582b8a42becdeac08bdead04f68eb752adda722d583c2a
ARG BETTERLEAKS_SHA256_ARM64=bbb578b12a2f65d7082ab436abf37724232bc71d8a078e3c41336574420f1b48
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${BUILD_ARCH}" in \
      amd64) arch=x64; sum="$BETTERLEAKS_SHA256_AMD64" ;; \
      arm64) arch=arm64; sum="$BETTERLEAKS_SHA256_ARM64" ;; \
      *) echo "Unsupported architecture: $BUILD_ARCH" >&2; exit 1 ;; \
    esac; \
    file="betterleaks_${BETTERLEAKS_VERSION}_linux_${arch}.tar.gz"; \
    curl -fsSL -o "/tmp/$file" \
      "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/$file"; \
    echo "$sum  /tmp/$file" | sha256sum -c -; \
    mkdir -p /opt/betterleaks; \
    tar -xzf "/tmp/$file" -C /opt/betterleaks betterleaks LICENSE; \
    chmod 0755 /opt/betterleaks/betterleaks; \
    test "$(/opt/betterleaks/betterleaks version)" = "$BETTERLEAKS_VERSION"

# Opengrep stable standalone distribution. Never an unpinned registry download at runtime.
FROM --platform=linux/amd64 debian:bookworm-slim AS opengrep
# amd64 only (see the FROM lines): not the predefined TARGETARCH, which follows the build command's platform.
ARG BUILD_ARCH=amd64
ARG OPENGREP_VERSION=1.30.2
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${BUILD_ARCH}" in \
      amd64) arch=x86; sum=a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7 ;; \
      arm64) arch=aarch64; sum=90acea5df4b733083f388d4feeb250ca802f671b33d1f222653d1e571dd2b0d8 ;; \
      *) exit 1 ;; \
    esac; \
    curl -fsSL -o /opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_${arch}"; \
    echo "$sum  /opengrep" | sha256sum -c -; chmod 0755 /opengrep

FROM --platform=linux/amd64 eclipse-temurin:21-jre-jammy AS runtime
ENV VIRTUAL_ENV=/opt/watchtower/pythonvenv
ENV PATH="/opt/watchtower/pythonvenv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY watchtower-core/src/main/resources/assistant/tree-sitter-requirements.txt /opt/watchtower/tree-sitter-requirements.txt
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && python3 -m venv "$VIRTUAL_ENV" \
    && "$VIRTUAL_ENV/bin/pip" install --no-cache-dir --upgrade pip \
    && "$VIRTUAL_ENV/bin/pip" install --no-cache-dir checkov==2.0.257 \
    && "$VIRTUAL_ENV/bin/pip" install --no-cache-dir -r /opt/watchtower/tree-sitter-requirements.txt \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin watchtoweruser \
    && mkdir -p /opt/watchtower/eslint_work \
    && npm --prefix /opt/watchtower/eslint_work install eslint@7.24.0 \
    && chown -R 1000:1000 /opt/watchtower

COPY --from=opengrep /opengrep /usr/local/bin/opengrep
COPY watchtower-module-opengrep/src/main/resources/licenses/ /usr/share/doc/opengrep/
ENV WATCHTOWER_OPENGREP_PATH=/usr/local/bin/opengrep

COPY --from=betterleaks /opt/betterleaks/betterleaks /usr/local/bin/betterleaks
COPY --from=betterleaks /opt/betterleaks/LICENSE /usr/share/doc/betterleaks/LICENSE
ENV WATCHTOWER_BETTERLEAKS_PATH=/usr/local/bin/betterleaks

COPY --from=build --chown=1000:1000 \
    /workspace/watchtower-web/target/watchtower*SNAPSHOT.jar /opt/watchtower/watchtower.jar

# Reviewed, secret-free fixtures for rule-candidate testing. Read-only data; only environments
# that set watchtower.rule-testing.fixture-directory use it (deploy.sh sets it for Dev only).
COPY --chown=1000:1000 rule-fixtures/ /opt/watchtower/rule-fixtures/

USER 1000:1000
WORKDIR /opt/watchtower
ENTRYPOINT ["java", "-jar", "/opt/watchtower/watchtower.jar"]
