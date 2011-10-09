require 'rubygems'

version_file = File.expand_path __FILE__ + '/../VERSION'
version = File.read(version_file).strip

spec_file = File.expand_path __FILE__ + '/../skinny.gemspec'
spec = Gem::Specification.load spec_file

require 'rdoc/task'
RDoc::Task.new :rdoc => "rdoc",
    :clobber_rdoc => "rdoc:clean",
    :rerdoc => "rdoc:force" do |rdoc|
  rdoc.title = "Skinny #{version}"
  rdoc.rdoc_dir = 'rdoc'
  rdoc.main = 'README.md'
  rdoc.rdoc_files.include 'lib/**/*.rb'
end

desc "Package as Gem"
task "package:gem" do
  builder = Gem::Builder.new spec
  builder.build
end

task "package" => ["package:gem"]

desc "Release Gem to RubyGems"
task "release:gem" do
  %x[gem push mailcatcher-#{version}.gem]
end

task "release" => ["package", "release:gem"]
