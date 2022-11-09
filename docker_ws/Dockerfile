FROM rust


# TODO Add service
ENV PATH /mangle_web_engine:$PATH
RUN rustup toolchain install nightly-x86_64-unknown-linux-gnu && rustup default nightly
RUN git clone https://github.com/manglemix/mangle_web_engine.git && \
    cd mangle_web_engine && \
    cargo build --release && \
    mv target/release/mangle_web_engine ../tmp && \
    cd .. && \
    rm -rf mangle_web_engine && \
    mv tmp mangle_web_engine