Gem::Specification.new do |s|
  s.name = "skinny"
  s.version = File.read(File.expand_path("../VERSION", __FILE__)).strip
  s.license = "MIT"
  s.summary = "Thin WebSockets"
  s.description = "Simple, upgradable WebSockets for Thin."

  s.author = "Samuel Cochran"
  s.email = "sj26@sj26.com"
  s.homepage = "http://github.com/sj26/skinny"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.date = "2010-11-01"

  s.files = Dir[
    "README.md", "LICENSE",
    "lib/**/*.rb",
  ]
  s.require_paths = ["lib"]
  s.extra_rdoc_files = ["README.md", "LICENSE"]

  s.required_ruby_version = ">= 1.8.7"

  s.add_dependency "eventmachine", ">= 1.0.0"
  s.add_dependency "thin", ">= 1.5", "< 1.7"

  s.add_development_dependency "rake"
  s.add_development_dependency "rdoc"
end
