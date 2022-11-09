FROM rust


# TODO Add service
RUN ["/bin/bash", "-c", "echo \"alias webrun='cd /mangle_web_engine && cargo run --release'\" >> /root/.bashrc"]
RUN rustup toolchain install nightly-x86_64-unknown-linux-gnu && rustup default nightly
RUN git clone https://github.com/manglemix/mangle_web_engine.git
RUN cd mangle_web_engine && cargo build --release && mv target/release/mangle_web_engine .. && cd .. && rm -rf mangle_web_engine