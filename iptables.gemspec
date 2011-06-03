Gem::Specification.new do |s|
  s.name = 'iptables'
  s.version = '0.0.1'
  s.homepage = 'https://github.com/rodjek/iptables/'
  s.summary = 'A Ruby DSL for creating iptables rules'
  s.description = <<-EOS.undent
    A Ruby DSL for creating iptables rules.
  EOS

  s.files = [
    'iptables.gemspec',
    'Rakefile',
    'README.md',
    'lib/iptables.rb',
    'spec/spec_helper.rb',
  ]

  s.add_development_dependency 'rspec'

  s.authors = ['Tim Sharpe']
  s.email = 'tim@sharpe.id.au'
end
