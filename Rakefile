require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "skinny"
    gem.summary = %Q{Thin WebSockets}
    gem.description = <<-EOD
      Simple, upgradable WebSockets for Thin.
    EOD
    gem.email = "sj26@sj26.com"
    gem.homepage = "http://github.com/sj26/skinny"
    gem.authors = ["Samuel Cochran"]
    
    gem.add_dependency 'eventmachine'
    gem.add_dependency 'thin'
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ""

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "skinny #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/*.rb')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
