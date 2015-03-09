require 'spec_helper'
require 'sequence_examples'

require 'nmap/tcp_ts_sequence'

describe TcpTsSequence do
  subject { @xml.hosts.first.tcp_ts_sequence }

  describe "#description" do
    it "should parse the description" do
      subject.description.should == "1000HZ"
    end
  end

  describe "#to_s" do
    let(:description_regexp) do
      /"[^"]+"/
    end

    let(:values_regexp) do
      /\[\d+(, \d+){5}\]/
    end

    let(:regexp) do
      /^description=#{description_regexp} values=#{values_regexp}$/
    end

    it "should contain the description and values" do
      subject.to_s.should =~ regexp
    end
  end

  it_should_behave_like "Sequence"
end
