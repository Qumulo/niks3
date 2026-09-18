{
  testers,
  writeText,
  s5cmd,
  niks3,
  rustfs,
  pkgs,
  ...
}:

# The read proxy fills its private bucket from an upstream binary cache.
# The upstream is a plain file:// cache signed with its own key and served
# by nginx; niks3 must serve those narinfos with the upstream signature
# intact for `nix copy` to accept them.
let
  niks3SecretKey = writeText "niks3-signing-key" "niks3-test-1:0knWkx/F+6IJmI4dkvNs14SCaewg9ZWSAQUNg9juRxh/8x+rzUJx9SWdyGOVl21IbJlQemUKG40qW2TTyrE++w==";
  niks3PublicKey = "niks3-test-1:f/Mfq81CcfUlnchjlZdtSGyZUHplChuNKltk08qxPvs=";
  upstreamSecretKey = writeText "upstream-signing-key" "upstream-test-1:ZDOdaX5bRL33rUCkc9WU/KMqBWNWbrzm81cw/vfCldqXgoTF8Rn0RThI2iNx61Vgq8mwvf9F5WAniuEptgbdwQ==";
  upstreamPublicKey = "upstream-test-1:l4KExfEZ9EU4SNojcetVYKvJsL3/ReVgJ4rhKbYG3cE=";
  apiToken = "test-token-that-is-at-least-36-characters-long";
in
testers.nixosTest {
  name = "nixos-test-pull-through";

  nodes.server = {
    imports = [ ../nixosModules/niks3.nix ];

    nix.settings = {
      experimental-features = [
        "nix-command"
        "flakes"
      ];
      substituters = [ ];
      trusted-public-keys = [
        niks3PublicKey
        upstreamPublicKey
      ];
    };

    services.niks3 = {
      enable = true;
      httpAddr = "0.0.0.0:5751";
      s3 = {
        endpoint = "localhost:9000";
        bucket = "niks3-test";
        useSSL = false;
        accessKeyFile = writeText "s3-access-key" "rustfsadmin";
        secretKeyFile = writeText "s3-secret-key" "rustfsadmin";
      };
      apiTokenFile = writeText "api-token" apiToken;
      signKeyFiles = [ niks3SecretKey ];
      readProxy = {
        enable = true;
        trustedKeys = [ upstreamPublicKey ];
        pullThrough.upstreams = [ "http://localhost:8080" ];
      };
    };

    # The upstream: a file:// binary cache behind nginx.
    services.nginx = {
      enable = true;
      virtualHosts.upstream = {
        listen = [
          {
            addr = "0.0.0.0";
            port = 8080;
          }
        ];
        root = "/var/cache/upstream";
      };
    };

    systemd.services.rustfs = {
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${rustfs}/bin/rustfs --address 0.0.0.0:9000 --access-key rustfsadmin --secret-key rustfsadmin /var/lib/rustfs";
        StateDirectory = "rustfs";
        DynamicUser = true;
      };
    };

    systemd.services.rustfs-setup = {
      after = [ "rustfs.service" ];
      requires = [ "rustfs.service" ];
      before = [ "niks3.service" ];
      wantedBy = [ "multi-user.target" ];
      environment = {
        S3_ENDPOINT_URL = "http://localhost:9000";
        AWS_ACCESS_KEY_ID = "rustfsadmin";
        AWS_SECRET_ACCESS_KEY = "rustfsadmin";
      };
      path = [ s5cmd ];
      script = ''
        for i in $(seq 60); do s5cmd ls 2>/dev/null && break; sleep 2; done
        s5cmd mb s3://niks3-test || true
      '';
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
    };

    systemd.services.niks3 = {
      after = [ "rustfs-setup.service" ];
      requires = [ "rustfs-setup.service" ];
    };

    environment.systemPackages = [
      niks3
      pkgs.curl
      s5cmd
    ];
  };

  testScript = ''
    server.wait_for_unit("niks3.service")
    server.wait_for_unit("nginx.service")
    server.wait_for_open_port(5751)
    server.wait_for_open_port(8080)

    # Build a path and publish it only to the upstream cache, signed with the upstream key.
    server.succeed("nix-build -E 'derivation { name=\"pull-test\"; system=builtins.currentSystem; builder=\"/bin/sh\"; args=[\"-c\" \"echo hello-pull > $out\"]; }' --no-out-link > /tmp/pull-path")
    server.succeed("mkdir -p /var/cache/upstream && chmod 755 /var/cache/upstream")
    server.succeed("nix copy --to 'file:///var/cache/upstream?secret-key=${upstreamSecretKey}' $(cat /tmp/pull-path)")
    server.succeed("chmod -R a+rX /var/cache/upstream")
    server.succeed("ls /var/cache/upstream/*.narinfo")

    hash = server.succeed("basename $(cat /tmp/pull-path) | cut -c1-32").strip()
    narinfo = f"http://localhost:5751/{hash}.narinfo"

    # First read is a miss filled from upstream; the upstream Sig is served untouched.
    server.succeed(f"curl -sfD /tmp/h1 {narinfo} > /tmp/n1")
    server.succeed("grep -i 'X-Cache-Status: MISS' /tmp/h1")
    server.succeed("grep '^Sig: upstream-test-1:' /tmp/n1")
    server.succeed(f"diff /tmp/n1 /var/cache/upstream/{hash}.narinfo")

    # Second read is served from the bucket, and so is a HEAD.
    server.succeed(f"curl -sfD /tmp/h2 {narinfo} > /tmp/n2")
    server.succeed("grep -i 'X-Cache-Status: HIT' /tmp/h2")
    server.succeed("diff /tmp/n1 /tmp/n2")
    server.succeed(f"curl -sfI {narinfo} | grep -i 'X-Cache-Status: HIT'")

    # A full nix copy through the proxy verifies the upstream signature end to end.
    server.succeed("nix copy --from http://localhost:5751 --to /tmp/pull-store $(cat /tmp/pull-path)")
    server.succeed("nix --store /tmp/pull-store store cat $(cat /tmp/pull-path) | grep hello-pull")

    # The NAR that copy pulled is filled behind the client and then served
    # from the bucket; both objects now live there.
    nar = server.succeed("grep '^URL:' /tmp/n1 | cut -d' ' -f2").strip()
    server.wait_until_succeeds(f"curl -sfD - -o /dev/null http://localhost:5751/{nar} | grep -i 'X-Cache-Status: HIT'")
    server.succeed(f"S3_ENDPOINT_URL=http://localhost:9000 AWS_ACCESS_KEY_ID=rustfsadmin AWS_SECRET_ACCESS_KEY=rustfsadmin s5cmd ls s3://niks3-test/{nar}")
    server.succeed(f"S3_ENDPOINT_URL=http://localhost:9000 AWS_ACCESS_KEY_ID=rustfsadmin AWS_SECRET_ACCESS_KEY=rustfsadmin s5cmd ls s3://niks3-test/{hash}.narinfo")

    # Paths the upstream lacks 404 and are remembered.
    server.succeed("test $(curl -so /dev/null -w '%{http_code}' http://localhost:5751/00000000000000000000000000000000.narinfo) = 404")
    server.succeed("curl -sD - -o /dev/null http://localhost:5751/00000000000000000000000000000000.narinfo | grep -i 'X-Cache-Status: NEGATIVE'")

    # A path the upstream signed with a key niks3 does not trust is refused,
    # never stored, and cannot be copied through the proxy.
    server.succeed("nix key generate-secret --key-name rogue-test-1 > /tmp/rogue.sec")
    server.succeed("nix-build -E 'derivation { name=\"rogue-test\"; system=builtins.currentSystem; builder=\"/bin/sh\"; args=[\"-c\" \"echo hello-rogue > $out\"]; }' --no-out-link > /tmp/rogue-path")
    server.succeed("nix copy --to 'file:///var/cache/upstream?secret-key=/tmp/rogue.sec' $(cat /tmp/rogue-path)")
    server.succeed("chmod -R a+rX /var/cache/upstream")

    rogue = server.succeed("basename $(cat /tmp/rogue-path) | cut -c1-32").strip()
    server.succeed(f"grep '^Sig: rogue-test-1:' /var/cache/upstream/{rogue}.narinfo")
    server.succeed(f"test $(curl -so /dev/null -w '%{{http_code}}' http://localhost:5751/{rogue}.narinfo) = 502")
    server.fail(f"S3_ENDPOINT_URL=http://localhost:9000 AWS_ACCESS_KEY_ID=rustfsadmin AWS_SECRET_ACCESS_KEY=rustfsadmin s5cmd ls s3://niks3-test/{rogue}.narinfo")
    server.fail("nix copy --from http://localhost:5751 --to /tmp/rogue-store $(cat /tmp/rogue-path)")
  '';
}
