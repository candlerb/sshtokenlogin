# sshtokenlogin

Inspired by [kubelogin](https://github.com/int128/kubelogin), this is a companion
client app to sshtokenca which will:

- open an ssh connection to sshtokenca
- open your browser to go to your identity provider
- receive the code response and forward it to sshtokenca
- accept the certificate into your ssh agent

## Usage

```
sshtokenlogin [-config sshtokenlogin.yaml] [<remote>...]
```

If the config filename is not provided, it defaults to
`~/.config/sshtokenlogin/sshtokenlogin.yaml`

`<remote>` selects one or more of the remote server configurations to
connect to.  If not specified then the entry called "default" is used.

## Configuration

```
# By default, a random port is opened to accept the response from the
# identity provider.  You can override this by giving a list of
# address:port.  The first one which is free is used.
#listen_addresses: [127.0.0.1:8000, 127.0.0.1:18000]
#
# Normally the redirect URI is http://localhost:<port>/callback.
# You can use this setting to replace "localhost".
#redirect_uri_hostname: 127.0.0.1

servers:
  default:
    # The name and port of the host to connect to
    host: mysshca.example.com:2222

    # The ssh username provided when connecting
    user: fred

    # You MUST verify the host key of the remote server, so you're
    # not sending openid credentials to an attacker, and not granting
    # access to your ssh agent to an untrusted host.
    # Copy /etc/ssh/ssh_host_XXX_key.pub from the remote host.
    # A multiline string can provide multiple keys for the same host.
    host_keys: <keytype> <keydata>

    # If you have an SSH host CA then instead you can give the CA key
    # (but make sure your host certificates always include principals)
    ca_keys: <keytype> <keydata>
```

# Security considerations

You must only ever connect with this program to a **TRUSTED HOST**.  This is
because:

* You will be sending your OpenID Connect response code to this host (who
  could use it to impersonate you)
* This host can connect to your SSH agent
* This host can redirect your browser to an arbitrary URL

It is your responsibility to put the correct host key in
`sshtokenlogin.yaml`.  The reason for this is so that a securely-distributed
`sshtokenlogin.yaml` also bundles the correct host key, eliminating TOFU
(Trust On First Use) warnings.

You can extract the key from an existing `known_hosts` file using ssh-keygen:

```
ssh-keygen -F mysshca.example.com:2222
ssh-keygen -F '[192.0.2.1]:2222'
```

On the flip side: if you are the *recipient* a `sshtokenlogin.yaml` file
claiming to be from your organisation, then at least check that the target
"host" is one you recognise.

Ideally you'd also take a signature or hash of the entire file and check it
against the originator, so you know that the host key has not been tampered
with.  If you cannot do that, then the first time you run sshtokenlogin with
this configuration, you should do it from a trusted network.  If the
connection is successful then the host key is correct.
