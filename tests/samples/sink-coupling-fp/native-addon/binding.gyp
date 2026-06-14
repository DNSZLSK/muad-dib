{
  "targets": [
    {
      "target_name": "bignum",
      "sources": [ "src/addon.cpp" ],
      "include_dirs": [ "<!(node -p \"require('node-addon-api').include_dir\")" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ]
    }
  ]
}
