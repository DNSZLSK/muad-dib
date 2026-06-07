{
  "targets": [
    {
      "target_name": "addon",
      "include_dirs": [ "<!(node -p \"require('node-addon-api').include\")" ],
      "sources": [ "<!(node ./util/has_lib.js)" ]
    }
  ]
}
