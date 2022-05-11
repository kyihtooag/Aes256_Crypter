defmodule Aes256CrypterTest do
  use ExUnit.Case
  doctest Aes256Crypter

  def plaintext_data do
    "This is plaintext"
  end

  def ciphertext do
  	"6yw/4J05fMjPaWQFtSScCKGAhlvnyHle94qxs4fQDck="
  end

  def salt do
  	<<1,2,3,4,5,6,7,8>>
  end

  def key do
  	"key"
  end

  def iterations do
  	1000
  end

  test "#encryption 256bit key" do
    encrypted_text = Aes256Crypter.encryption(plaintext_data(), key(), salt(), iterations())
    assert encrypted_text === ciphertext()
  end

  test "#decryption with 256bit key" do
    plaintext = Aes256Crypter.decryption(ciphertext(), key(), salt(), iterations())
    assert plaintext === plaintext_data()
  end

end
