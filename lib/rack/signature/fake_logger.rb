module Rack
  class Signature
    class FakeLogger
      def debug(_value)
        nil
      end

      def warn(_value)
        nil
      end

      def <<(_value)
        nil
      end

      def info(_value)
        nil
      end
    end
  end
end
