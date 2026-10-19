require 'xcodeproj'
# Generate the project IN this directory (poc/signer-app/), referencing Sources/main.swift here.
Dir.chdir(__dir__)
proj_path = File.join(__dir__, 'LokiSigner.xcodeproj')
project = Xcodeproj::Project.new(proj_path)
target = project.new_target(:application, 'LokiSigner', :osx, '13.0')
src = project.new_file('Sources/main.swift')
target.add_file_references([src])
target.build_configurations.each do |c|
  bs = c.build_settings
  bs['PRODUCT_BUNDLE_IDENTIFIER'] = 'cash.loki.signer'
  bs['PRODUCT_NAME'] = 'LokiSigner'
  bs['CODE_SIGN_STYLE'] = 'Automatic'
  bs['DEVELOPMENT_TEAM'] = 'B399KAT22M'
  bs['CODE_SIGN_ENTITLEMENTS'] = 'LokiSigner.entitlements'
  bs['SWIFT_VERSION'] = '5.0'
  bs['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
  bs['GENERATE_INFOPLIST_FILE'] = 'YES'
  bs['CODE_SIGN_IDENTITY'] = 'Apple Development'
end
project.save
puts "project generated"
