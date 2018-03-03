$:.push File.expand_path("../lib", __FILE__)
require "saml_idp/version"

Gem::Specification.new do |s|
  s.name = %q{ruby-saml-idp}
  s.version = SamlIdp::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = ["Lawrence Pit"]
  s.email = %q{lawrence.pit@gmail.com}
  s.homepage = %q{http://github.com/lawrencepit/ruby-saml-idp}
  s.summary = %q{SAML Indentity Provider in ruby}
  s.description = %q{SAML IdP (Identity Provider) library in ruby}
  s.license = "MIT"

  s.date = Time.now.utc.strftime("%Y-%m-%d")
  s.files = Dir.glob("app/**/*") + Dir.glob("lib/**/*") + [
     "MIT-LICENSE",
     "README.md",
     "Gemfile",
     "ruby-saml-idp.gemspec"
  ]
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.rdoc_options = ["--charset=UTF-8"]
  s.add_development_dependency("rake")
  s.add_development_dependency("ruby-saml")
  s.add_development_dependency("nokogiri")
  s.add_development_dependency("rspec", "~> 3.0")
  s.add_development_dependency("rails", "~> 3.2")
  s.add_development_dependency("capybara", "~> 2.4.1")
  s.add_development_dependency("timecop", "~> 0.9.0")
end

