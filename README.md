# sshtokenlogin

Inspired by [kubelogin](https://github.com/int128/kubelogin), this is a companion
client app to sshtokenca which will:

- open an ssh connection to sshtokenca
- open your browser to go to your identity provider
- receive the code response and forward it to sshtokenca
- accept the certificate into your ssh agent

## Usage

```
sshtokenlogin [-config settings.yaml] [<remote>...]
```

`<remote>` selects one or more of the remote server configurations to
connect to.  If not specified then the entry called "default" is used.

## Configuration

TODO
