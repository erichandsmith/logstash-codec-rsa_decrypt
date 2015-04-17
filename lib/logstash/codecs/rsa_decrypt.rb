# encoding: utf-8
require "logstash/codecs/base"
require "logstash/namespace"
require "logstash/json"
require "logstash/util/charset"

class LogStash::Codecs::RsaDecrypt < LogStash::Codecs::Base
  config_name "rsa_decrypt"

  # The location of the private key file.
  config :private_key_file, :validate => :path, :required => true
  config :passphrase, :validate => :string, :default => ""
  config :charset, :validate => ::Encoding.name_list, :default => "UTF-8"

  public
  def initialize(params={})
    super(params)
    require "openssl"
    require "base64"

    if @passphrase.to_s != ""
        @private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), @passphrase)
    else
        @private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file))
    end

    @converter = LogStash::Util::Charset.new(@charset)
    @converter.logger = @logger
  end

  public
  def decode(data)

    # Ensure the data is a string.
    data_string = @converter.convert(data)

    # Convert the string to a hash table.
    data_json = LogStash::Json.load(data_string)

    # Splitting these out for readability...
    base64_encrypted_data = data_json["encrypted_data"]
    base64_encrypted_key = data_json["encrypted_key"]
    base64_encrypted_iv = data_json["encrypted_iv"]

    # Base64 decode the data and session key (might make this optional in the future).
    encrypted_data = Base64.decode64(base64_encrypted_data)
    encrypted_key = Base64.decode64(base64_encrypted_key)
    encrypted_iv = Base64.decode64(base64_encrypted_iv)

    # Decrypt the session key with the private key.
    decrypted_key = @private_key.private_decrypt(encrypted_key)
    decrypted_iv = @private_key.private_decrypt(encrypted_iv)

    # Create the cipher from the session key.
    cipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
    cipher.decrypt
    cipher.key = decrypted_key
    cipher.iv = decrypted_iv

    # Decript the data with the cipher.
    decrypted_json = cipher.update(encrypted_data)
    decrypted_json << cipher.final

    # Convert the decrypted_data to a hash table and return a new event.
    decrypted_data = LogStash::Json.load(decrypted_json)
    yield LogStash::Event.new(decrypted_data)

  end # def encode

end # class LogStash::Codecs::RsaDecrypt
