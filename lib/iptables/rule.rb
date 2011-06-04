module IPTables
  class Rule
    attr_accessor :chain, :source, :destination, :target, :in_interface, :out_interface
    attr_reader :protocol, :modules
    attr_accessor :mod_opts

    def initialize
      @mod_opts = {}
      @modules = []
    end

    def add_module(val)
      modules = {
        :state => IPTables::Match::State,
      }

      begin
        self.extend(modules[val.to_sym])
        @modules << val.to_sym
      rescue
        raise "Unknown module '#{val}'"
      end
    end

    def protocol=(value)
      protocols = {
        :tcp => IPTables::Protocol::TCP,
        :udp => IPTables::Protocol::UDP,
      }

      value = value.to_sym unless value.is_a? Symbol
      @protocol = value
      begin
        self.extend(protocols[value.to_sym])
      rescue
        raise "Unknown protocol '#{value.to_s}'"
      end
    end

    def to_iptables
      data = []
      chain = @chain.to_s.upcase
      data << "-A" << chain

      if ['INPUT', 'FORWARD', 'PREROUTING'].include? chain
        unless @in_interface.nil?
          data << "-i" << @in_interface
        end
      end

      if ['OUTPUT', 'FORWORD', 'POSTROUTING'].include? chain
        unless @out_interface.nil?
          data << '-o' << @out_interface
        end
      end

      unless @source.nil?
        data << "-s" << @source
      end

      unless @destination.nil?
        data << "-d" << @destination
      end

      unless @protocol.nil?
        data << "-p" << @protocol
        @mod_opts[:protocol].each { |r| data << r }
      end

      @modules.each { |mod|
        data << '-m' << mod.to_s
        @mod_opts[mod].each { |r| data << r }
      }

      data << "-j" << @target.to_s.upcase
      data.join(' ')
    end
  end
end
