module IPTables
  module Protocol
    module UDP
      attr_reader :source_port, :destination_port

      def self.extended(base)
        base.mod_opts[:protocol] = []
      end

      def source_port=(value)
        value = value.to_i
        unless value > 0
          raise "UDP source port must be a valid integer greater than 0"
        end

        @source_port = value
        @mod_opts[:protocol] << "--sport" << source_port
      end

      def destination_port=(value)
        value = value.to_i
        unless value > 0
          raise "UDP destination port must be a valid integer greater than 0"
        end

        @destination_port = value
        @mod_opts[:protocol] << "--dport" << destination_port
      end
    end
  end
end
