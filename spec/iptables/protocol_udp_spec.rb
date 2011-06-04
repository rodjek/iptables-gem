require 'spec_helper'

describe IPTables::Rule do
  describe "when protocol is udp" do
    subject do
      rule = IPTables::Rule.new
      rule.protocol = :udp
      rule
    end

    its(:protocol) { should == :udp }

    it { should respond_to(:source_port).with(0).arguments }
    it { should respond_to(:source_port=).with(1).argument }
    it { should respond_to(:destination_port).with(0).arguments }
    it { should respond_to(:destination_port=).with(1).argument }

    context "and creating a rule with source_port" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.protocol = :udp
        rule.source_port = 80
        rule
      end

      its(:source_port) { should == 80 }
      its(:to_iptables) {
        should == "-A INPUT -p udp --sport 80 -j ACCEPT"
      }
    end

    context "and creating a rule with destination_port" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.protocol = :udp
        rule.destination_port = 443
        rule
      end

      its(:destination_port) { should == 443 }
      its(:to_iptables) {
        should == "-A INPUT -p udp --dport 443 -j ACCEPT"
      }
    end
  end
end
