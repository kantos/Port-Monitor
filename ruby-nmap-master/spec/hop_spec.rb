require 'spec_helper'
require 'nmap/hop'

describe Hop do
  describe "#to_s" do
    subject do
      described_class.new('10.0.0.1', nil, '1', '3.38')
    end

    it "should return the addr" do
      subject.to_s.should == subject.addr
    end
  end
end
