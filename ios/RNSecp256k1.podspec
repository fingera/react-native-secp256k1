
Pod::Spec.new do |s|
  s.name         = "RNSecp256k1"
  s.version      = "1.0.0"
  s.summary      = "RNSecp256k1"
  s.description  = <<-DESC
                  RNSecp256k1
                   DESC
  s.homepage     = ""
  s.license      = "MIT"
  # s.license      = { :type => "MIT", :file => "FILE_LICENSE" }
  s.author             = { "author" => "author@domain.cn" }
  s.platform     = :ios, "7.0"
  s.source       = { :git => "https://github.com/author/RNSecp256k1.git", :tag => "master" }
  s.source_files  = "RNSecp256k1/**/*.{h,m}"
  s.requires_arc = true


  s.dependency "React"
  #s.dependency "others"

end

  