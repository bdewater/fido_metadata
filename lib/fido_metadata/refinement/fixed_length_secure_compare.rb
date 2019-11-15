# frozen_string_literal: true

require "openssl"

module FidoMetadata
  module Refinement
    module FixedLengthSecureCompare
      unless OpenSSL.singleton_class.method_defined?(:fixed_length_secure_compare)
        refine OpenSSL.singleton_class do
          def fixed_length_secure_compare(a, b) # rubocop:disable Naming/UncommunicativeMethodParamName
            raise ArgumentError, "inputs must be of equal length" unless a.bytesize == b.bytesize

            # borrowed from Rack::Utils
            l = a.unpack("C*")
            r, i = 0, -1
            b.each_byte { |v| r |= v ^ l[i += 1] }
            r == 0
          end
        end
      end
    end
  end
end
