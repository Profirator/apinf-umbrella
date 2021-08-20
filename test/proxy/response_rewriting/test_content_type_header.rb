require_relative "../../test_helper"

class Test::Proxy::ResponseRewriting::TestContentTypeHeader < Minitest::Test
  include ApiUmbrellaTestHelpers::Setup
  parallelize_me!

  def setup
    super
    setup_server
  end

  def test_does_not_change_existing_content_type
    response = Typhoeus.get("http://127.0.0.1:9080/api/compressible/1000?content_type=Qwerty", http_options)
    assert_response_code(200, response)
    assert_equal("Qwerty", response.headers["content-type"])
  end
end
