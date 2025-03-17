sudo RUST_BACKTRACE=1 /home/ubuntu/dev/falcosecurity/falco/build/userspace/falco/falco \
    -c /home/ubuntu/dev/falcosecurity/falco/falco.yaml \
    -o 'plugins[]={"name":"krsi","library_path":"/home/ubuntu/dev/krsi/target/debug/libkrsi.so"}' \
    -o load_plugins[]=krsi \
    -o rules_files[]=./example_rule.yaml

