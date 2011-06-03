module IPTables
  module Protocol
    module TCP
      attr_accessor :destination_port, :tcp_flags, :syn, :tcp_option, :mss
      attr_reader :source_port

      def self.extended(base)
        base.mod_opts[:protocol] = []
      end

      def source_port=(value)
        value = value.to_i
        unless value > 0
          raise "TCP source port must be a valid integer greater than 0"
        end

        @source_port = value
        @mod_opts[:protocol] << "--sport" << source_port
      end

      def destination_port=(value)
        value = value.to_i
        unless value > 0
          raise "TCP destination port must be a valid integer greater than 0"
        end

        @destination_port = value
        @mod_opts[:protocol] << "--dport" << destination_port
      end

      def tcp_flags=(value)
        unless value.is_a? Hash
          raise "TCP flags must be a hash containing {:mask => [<flags>], :comp => [<flags>]}"
        end

        unless value.keys.include? :mask
          raise "TCP flags hash must include the :mask flags"
        end

        unless value.keys.include? :comp
          raise "TCP flags hash must include the :comp flags"
        end

        value[:not] == false if value[:not].nil?
        @tcp_flags = value
        @mod_opts[:protocol] << "--tcp-flags"
        @mod_opts[:protocol] << "!" if tcp_flags[:not] == true
        @mod_opts[:protocol] << tcp_flags[:mask].map { |r| r.to_s.upcase }.join(',')
        @mod_opts[:protocol] << tcp_flags[:comp].map { |r| r.to_s.upcase }.join(',')
      end
    end
  end
end
