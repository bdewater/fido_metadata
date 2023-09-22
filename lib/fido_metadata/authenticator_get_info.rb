# frozen_string_literal: true

require "fido_metadata/attributes"

module FidoMetadata
  class AuthenticatorGetInfo
    extend Attributes

    json_accessor("versions")
    json_accessor("extensions")
    json_accessor("aaguid")
    json_accessor("options")
    json_accessor("maxMsgSize")
    json_accessor("pinUvAuthProtocols")
    json_accessor("maxCredentialCountInList")
    json_accessor("maxCredentialIdLength")
    json_accessor("transports")
    json_accessor("algorithms")
    json_accessor("maxSerializedLargeBlobArray")
    json_accessor("forcePINChange")
    json_accessor("minPINLength")
    json_accessor("firmwareVersion")
    json_accessor("maxCredBlobLength")
    json_accessor("maxRPIDsForSetMinPINLength")
    json_accessor("preferredPlatformUvAttempts")
    json_accessor("uvModality")
    json_accessor("certifications")
    json_accessor("remainingDiscoverableCredentials")
    json_accessor("vendorPrototypeConfigCommands")
  end
end
