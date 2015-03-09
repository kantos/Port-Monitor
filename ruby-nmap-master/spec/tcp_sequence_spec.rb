require 'spec_helper'
require 'sequence_examples'

require 'nmap/tcp_sequence'

describe TcpSequence do
  subject { @xml.hosts.first.tcp_sequence }

  describe "#index" do
    it "should parse the index" do
      subject.index.should be > 0
    end
  end

  describe "#description" do
    it "should parse the difficulty description" do
      subject.difficulty.should == "Good luck!"
    end
  end

  describe "#to_s" do
    let(:index_regexp) do
      /\d+/
    end

    let(:difficulty_regexp) do
      /"(Good luck!)"/
    end

    let(:values_regexp) do
      /\[\d+(, \d+){5}\]/
    end

    let(:regexp) do
      /^index=#{index_regexp} difficulty=#{difficulty_regexp} values=#{values_regexp}$/
    end

    it "should contain the description and values" do
      subject.to_s.should =~ regexp
    end
  end

  it_should_behave_like "Sequence"
end
