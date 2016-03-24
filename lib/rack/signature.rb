require 'signatures/validators/basic'
require 'rack/signature/signable_extractor'
require 'rack/signature/fake_logger'

module Rack
  class Signature
    TIMESTAMP_HEADER = 'HTTP_TIMESTAMP'.freeze
    SIGNATURE_HEADER = 'HTTP_SIGNATURE'.freeze
    SIGNATURE_KEY_HEADER = 'HTTP_SIGNATURE_KEY'.freeze
    SIGNATURE_ENV = 'SIGNATURE'.freeze

    attr_reader :app, :validator, :signable_elms, :signable_extractor, :keystore, :logger

    def initialize(app, opts = {})
      self.app = app
      self.keystore = opts.fetch :keystore, {}
      self.validator = opts.fetch :validator, default_validator
      self.signable_elms = opts.fetch :signable_elms, [:params, :body, :path, :timestamp]
      self.signable_extractor = opts.fetch :signable_extractor, SignableExtractor
      self.logger = opts.fetch :logger, FakeLogger.new
    end

    def call(env)
      env[SIGNATURE_ENV] ||= signature_params(env)
      logger.info("[#{Time.now}][Rack][Signature] Invalid Signature - Request signature: #{signature(env)} - Text to sign: #{signable(env)} ") unless signature_params[:valid]
      app.call env
    end

    private

    def signature(env)
      env[SIGNATURE_HEADER]
    end

    def timestamp(env=nil)
      env[TIMESTAMP_HEADER]
    end

    def signature_key(env=nil)
      env[SIGNATURE_KEY_HEADER]
    end

    def default_validator
      @default_validator ||= Signatures::Validators::Basic.new(keystore: keystore)
    end

    def signature_params(env=nil)
      @signature_params ||= {
        value: signature(env),
        present: !signature(env).nil?,
        valid: validator.call(
          to_validate: signable(env),
          signature: signature(env),
          timestamp: timestamp(env),
          key: signature_key(env)
        ),
        key_known: !!keystore[signature_key(env)]
      }
    end

    def signable(env=nil)
      @signable ||= signable_extractor.call Rack::Request.new(env), signable_elms
    end

    private

    attr_writer :app, :validator, :signable_elms, :signable_extractor, :keystore, :logger
  end
end
