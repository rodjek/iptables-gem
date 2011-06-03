require 'spec_helper'

describe IPTables::Rule do
  describe "when protocol is tcp" do
    subject do
      rule = IPTables::Rule.new
      rule.protocol = :tcp
      rule
    end

    its(:protocol) { should == :tcp }

    it { should respond_to(:source_port).with(0).arguments }
    it { should respond_to(:source_port=).with(1).argument }
    it { should respond_to(:destination_port).with(0).arguments }
    it { should respond_to(:destination_port=).with(1).argument }
    it { should respond_to(:tcp_flags).with(0).arguments }
    it { should respond_to(:tcp_flags=).with(1).argument }
    it { should respond_to(:syn).with(0).arguments }
    it { should respond_to(:syn=).with(1).arguments }
    it { should respond_to(:tcp_option).with(0).arguments }
    it { should respond_to(:tcp_option=).with(1).argument }
    it { should respond_to(:mss).with(0).arguments }
    it { should respond_to(:mss=).with(1).argument }

    context "when creating a rule with source_port" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.protocol = :tcp
        rule.source_port = 80
        rule
      end

      its(:source_port) { should == 80 }
      its(:to_iptables) {
        should == "-A INPUT -p tcp --sport 80 -j ACCEPT"
      }
    end

    context "when creating a rule with destination_port" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.protocol = :tcp
        rule.destination_port = 443
        rule
      end

      its(:destination_port) { should == 443 }
      its(:to_iptables) {
        should == "-A INPUT -p tcp --dport 443 -j ACCEPT"
      }
    end

    context "when creating a rule with tcp_flags" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.protocol = :tcp
        rule.tcp_flags = {:mask => [:syn, :rst, :ack, :fin], :comp => [:syn]}
        rule
      end

      its(:tcp_flags) { should == {:mask => [:syn, :rst, :ack, :fin], :comp => [:syn]} }
      its(:to_iptables) {
        should == "-A INPUT -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -j ACCEPT"
      }
    end

    context "when creating a rule with tcp_flags inverted" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.protocol = :tcp
        rule.tcp_flags = {:mask => [:syn, :rst, :ack, :fin], :comp => [:syn], :not => true}
        rule
      end

      its(:tcp_flags) { should == {:mask => [:syn, :rst, :ack, :fin], :comp => [:syn], :not => true} }
      its(:to_iptables) {
        should == "-A INPUT -p tcp --tcp-flags ! SYN,RST,ACK,FIN SYN -j ACCEPT"
      }
    end
  end
end
