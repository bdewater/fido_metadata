# FidoMetadata

A Ruby gem for the [FIDO Alliance Metadata Service (MDS)](https://fidoalliance.org/metadata/). The MDS is a way to retrieve data about FIDO2 and U2F authenticators such as make, model, biometric capabilities, security status and the manufacturer root certificate(s). See [FIDO TechNotes: The Truth about Attestation](https://fidoalliance.org/fido-technotes-the-truth-about-attestation/) for a generic overview.

This gem provides a HTTP client for the MDS that performs the necessary security checks, parses the data into objects, and caches the results for speed and resiliency. It is intended to be used by WebAuthn relying parties wishing to verify attestation statement during registration.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'fido_metadata'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install fido_metadata

## Usage

First, you need to [register for an access token](https://mds2.fidoalliance.org/tokens/). You can configure the gem as follows:
```ruby
FidoMetadata.configure do |config|
  config.metadata_token = "your token"
end
```

Then you can query the table of contents (TOC):
```ruby
store = FidoMetadata::Store.new
toc = store.table_of_contents
# `toc.entries` returns an array of FidoMetadata::Entry objects, see
# https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-metadata-service-v2.0-ps-20170927.html#metadata-toc-payload-entry-dictionary
  
```

Retrieve metadata statement via the authenticator `aaguid` (FIDO2) or `attestation_certificate_key_id` (U2F):
```ruby
store.fetch_statement(aaguid: "0132d110-bf4e-4208-a403-ab4f5f12efe5")
# returns a FidoMetadata::Statement object, see
# https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-metadata-statement-v2.0-ps-20170927.html#types
```

### Integrating the cache backend
    
The cache interface is compatible with Rails' [`ActiveSupport::Cache::Store`](https://api.rubyonrails.org/classes/ActiveSupport/Cache/Store.html), which means you can configure the gem to use your existing cache or a separate one: 

```ruby
FidoMetadata.configure do |config|
  config.cache_backend = Rails.cache # or something like `ActiveSupport::Cache::FileStore.new(...)`
end
``` 

It is also possible to implement your own backend for using any datastore you'd like, such as your database. The interface you need to implement is as follows:

```ruby
class CustomMetadataCacheStore
  def read(name, _options = nil)
    # deserialize and return `value`
  end
  def write(name, value, _options = nil)
    # serialize and store `value` so it can be looked up using `name`
  end
end

# and configure the gem to use it:
FidoMetadata.configure do |config|
  config.cache_backend = CustomMetadataCacheStore.new
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/rspec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/bdewater/fido_metadata. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

The gem and its authors are unaffiliated with the FIDO Alliance. The FIDO and FIDO ALLIANCE trademarks and logos are trademarks of FIDO Alliance, Inc.
