require 'spec_helper'

describe IPTables::Rule do
  context "when creating complex rules" do
    describe "like allow traffic in on eth1 from 10.0.0.0/24 on port 443 with a new state" do
      subject do
        rule = IPTables::Rule.new
        rule.chain = :input
        rule.target = :accept
        rule.protocol = :tcp
        rule.source = '10.0.0.0/24'
        rule.destination_port = 443
        rule.add_module 'state'
        rule.state = :new
        rule.in_interface = 'eth1'
        rule
      end

      its(:to_iptables) {
        should == '-A INPUT -i eth1 -s 10.0.0.0/24 -p tcp --dport 443 -m state --state NEW -j ACCEPT'
      }
    end
  end
end
