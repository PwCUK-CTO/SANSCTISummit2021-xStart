# xStart auto-config decoder
The xStart auto-config decoder is a Python 3 script run against samples of xStart that can parse the AES-128 key, use it to decode the PE resources, and then return the configuration of the shellcode used to download the next stage Cobalt Strike payloads.

## Installing requirements
```
pip install -r requirements.txt
```

## Usage
```
usage: xstart_auto_config_extract.py [-h] --input INPUT [--output OUTPUT] [--key KEY]
                              [--debug]

Auto decode xStart resources

optional arguments:
  -h, --help       show this help message and exit
  --input INPUT    the xStart binary to have its resources decoded
  --output OUTPUT  (optional) the output folder to save the resources to
                   (default: the SHA256 of the provided input, prepended with
                   "output")
  --key KEY        (optional) the AES-128 CBC to use to decode xStart
                   resources
  --debug          run in debug mode (default:False)
```

## Example output
```
DEBUG:xstart_config_decoder:Parsing: "wwlib.dll_"
DEBUG:xstart_config_decoder:Parsed PE.
DEBUG:xstart_config_decoder:Loading xStart resources.
INFO:xstart_config_decoder:Loaded xStart resources: dict_keys(['MKV', 'MP4'])
DEBUG:xstart_config_decoder:Parsing AES-128 CBC key.
DEBUG:xstart_config_decoder:Key candidates: ['SeDebugPrivilege', '2a3b3CGKSWCGKOWD']
DEBUG:xstart_config_decoder:Removing FPs from key candidates.
INFO:xstart_config_decoder:Parsed AES key: 2a3b3CGKSWCGKOWD
DEBUG:xstart_config_decoder:Decrypting resources.
DEBUG:xstart_config_decoder:Resources decrypted.
INFO:xstart_config_decoder:Saving decoded resources to "output_4464be687305f8b23be470b4167c1d9eda39c1dac9d19fa3e2e89d78491c3a15".
INFO:xstart_config_decoder:Parsed domains from shellcode
INFO:xstart_config_decoder:cnooc.aliyunsdn.com
INFO:xstart_config_decoder:Parsed HTTP headers from shellcode
INFO:xstart_config_decoder:Accept: */*;
INFO:xstart_config_decoder:Accept-Language: en-US,en;q=0.5
INFO:xstart_config_decoder:Accept-Encoding: gzip, deflate
INFO:xstart_config_decoder:User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0
INFO:xstart_config_decoder:Parsed URI path from shellcode
INFO:xstart_config_decoder:/cdn/status_push
INFO:xstart_config_decoder:Saving config to "output_4464be687305f8b23be470b4167c1d9eda39c1dac9d19fa3e2e89d78491c3a15".
INFO:xstart_config_decoder:Decoder finished running!
```

## Example saved config (JSON)
```yaml
{
    "domains": [
        "cnooc.aliyunsdn.com"
    ],
    "http_headers": [
        "Accept: */*;",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"
    ],
    "path": [
        "/cdn/status_push"
    ]
}
```