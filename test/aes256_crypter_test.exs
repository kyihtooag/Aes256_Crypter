defmodule Aes256CrypterTest do
  use ExUnit.Case
  doctest Aes256Crypter

  test "greets the world" do
    assert Aes256Crypter.hello() == :world
  end
end
