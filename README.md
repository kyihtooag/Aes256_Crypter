# Aes256Crypter
Aes 256 encryption/decryption using Key Derivation with salt implementation in Elixir. 

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `aes256_crypter` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:aes256_crypter, "~> 0.1.0"}
  ]
end
```

## Building

`erlang-pbkdf2` which is used in this project uses rebar to manage the build process. To build the project, run:

```
	rebar compile
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/aes256_crypter](https://hexdocs.pm/aes256_crypter).

