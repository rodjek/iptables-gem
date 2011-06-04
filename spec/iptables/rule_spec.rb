require 'spec_helper'

describe IPTables::Rule do
  context "responds to" do
    subject { described_class.new }

    it { should respond_to(:chain).with(0).arguments }
    it { should respond_to(:chain=).with(1).argument }
    it { should respond_to(:protocol).with(0).arguments }
    it { should respond_to(:protocol=).with(1).argument }
    it { should respond_to(:source).with(0).arguments }
    it { should respond_to(:source=).with(1).argument }
    it { should respond_to(:destination).with(0).arguments }
    it { should respond_to(:destination=).with(1).argument }
    it { should respond_to(:target).with(0).arguments }
    it { should respond_to(:target=).with(1).argument }
    it { should respond_to(:in_interface).with(0).arguments }
    it { should respond_to(:in_interface=).with(1).argument }
    it { should respond_to(:out_interface).with(0).arguments }
    it { should respond_to(:out_interface=).with(1).argument }
    it { should respond_to(:modules).with(0).arguments }
    it { should respond_to(:add_module).with(1).argument }
  end

  context "when generating a simple rule to allow inbound traffic from 192.168.0.1 to 192.168.0.2" do
    subject do
      rule = IPTables::Rule.new
      rule.chain = :input
      rule.source = '192.168.0.1'
      rule.destination = '192.168.0.2'
      rule.target = :accept
      rule
    end

    its(:chain) { should == :input }
    its(:source) { should == '192.168.0.1' }
    its(:destination) { should == '192.168.0.2' }
    its(:target) { should == :accept }
    its(:to_iptables) {
      should == "-A INPUT -s 192.168.0.1 -d 192.168.0.2 -j ACCEPT"
    }
  end
end
