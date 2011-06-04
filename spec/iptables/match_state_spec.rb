require 'spec_helper'

describe IPTables::Rule do
  describe "when matching on state" do
    subject do
      rule = IPTables::Rule.new
      rule.add_module 'state'
      rule
    end

    its(:modules) { should == [:state] }

    it { should respond_to(:state).with(0).arguments }
    it { should respond_to(:state=).with(1).argument }

    context "and creating a rule with a single state" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :reject
        rule.add_module 'state'
        rule.state = :invalid
        rule
      end

      its(:state) { should == :invalid }
      its(:to_iptables) {
        should == "-A INPUT -m state --state INVALID -j REJECT"
      }
    end

    context "and creating a rule with multiple states" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.add_module 'state'
        rule.state = [:related, :established]
        rule
      end

      its(:state) { should == [:related, :established] }
      its(:to_iptables) {
        should == "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
      }
    end
  end
end
