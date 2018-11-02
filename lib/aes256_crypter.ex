defmodule Aes256Crypter do
  @moduledoc """
  Documentation for Aes256Crypter.
  """

  def encryption(plaintext, secret_key, salt, iterations)

  def encryption(plaintext, secret_key, salt, iterations) do
    palinByte = pkcs7_pad(plaintext)
    originalPassword = :crypto.hash(:sha256, secret_key)

    {ok, key_with_iv} = :pbkdf2.pbkdf2({:hmac, :sha}, originalPassword, salt, iterations, 48)

    key = Kernel.binary_part(key_with_iv, 0, 32)
    iv = Kernel.binary_part(key_with_iv, 32, 16)

    result = :crypto.block_encrypt(:aes_cbc256, key, iv, palinByte)
    Base.encode64(result)

  end

  def decryption(ciphertext, derivation_key, salt, iterations)

  def decryption(ciphertext, derivation_key, nil, salt, iterations) do
    raise "IV(initialization vector) is required to decrypt your ciphertext"
  end

  def decryption(ciphertext, derivation_key, salt, iterations) do
    cipherByte = Base.decode64!(ciphertext, mixed: true)
    originalPassword = :crypto.hash(:sha256, derivation_key)

    {ok, key_with_iv} = :pbkdf2.pbkdf2({:hmac, :sha}, originalPassword, salt, iterations, 48)

    key = Kernel.binary_part(key_with_iv, 0, 32)
    iv = Kernel.binary_part(key_with_iv, 32, 16)

    padded = :crypto.block_decrypt(:aes_cbc256, key, iv, cipherByte)

    case pkcs7_unpad(padded) do
      {:ok, plaintext} -> plaintext
      result -> result
    end
  end

  # Pads a message using the PKCS #7 cryptographic message syntax.
  #
  # See: https://tools.ietf.org/html/rfc2315
  # See: `pkcs7_unpad/1`
  defp pkcs7_pad(message) do
    bytes_remaining = rem(byte_size(message), 16)
    padding_size = 16 - bytes_remaining
    message <> :binary.copy(<<padding_size>>, padding_size)
  end

  # Unpads a message using the PKCS #7 cryptographic message syntax.
  #
  # See: https://tools.ietf.org/html/rfc2315
  # See: `pkcs7_pad/1`
  defp pkcs7_unpad(<<>>), do: :error
  defp pkcs7_unpad(message) do
    padding_size = :binary.last(message)
    if padding_size <= 16 do
      message_size = byte_size(message)
      if binary_part(message, message_size, -padding_size) === :binary.copy(<<padding_size>>, padding_size) do
        {:ok, binary_part(message, 0, message_size - padding_size)}
      else
        :error
      end
    else
      :error
    end
  end

  def generate_secret_key(key_size \\ 32) do
    if is_integer(key_size) do
      Base.encode64(:crypto.strong_rand_bytes(key_size))
    else
      :error
    end
  end

  def generate_salt(salt_size \\ 32) do
    if is_integer(salt_size) do
      :crypto.strong_rand_bytes(salt_size)
    else
      :error
    end
  end


end
