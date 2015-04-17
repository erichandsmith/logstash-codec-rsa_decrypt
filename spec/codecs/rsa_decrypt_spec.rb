# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/rsa_decrypt"
require "logstash/event"

describe LogStash::Codecs::RsaDecrypt do
  subject do
    next LogStash::Codecs::RsaDecrypt.new
  end

  context "#encode" do
    let (:event) {LogStash::Event.new({"message" => "hello world", "host" => "test"})}

    it "should return a json string" do
    end

  end
end
