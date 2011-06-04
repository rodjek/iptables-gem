module IPTables
  module Match
    module State
      attr_reader :state

      def self.extended(base)
        base.mod_opts[:state] = []
      end

      def state=(value)
        @state = value
        value = [value].flatten
        value.map! { |r| r.to_s.upcase }

        value.each do |r|
          unless ['INVALID', 'ESTABLISHED', 'RELATED', 'NEW'].include? r
            raise "'#{r}' is not a valid connection state"
          end
        end

        @mod_opts[:state] << "--state" << value.join(',')
      end
    end
  end
end
