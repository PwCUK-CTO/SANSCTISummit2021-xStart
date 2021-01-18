from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import binascii
import argparse
import logging
import pefile
import re
import os
import json


class HelperMethods:
    """
    Static methods that can be reused for other classes
    """

    @staticmethod
    def decode_array_of_byte_strings(array):

        output = []
        for byte_str in array:
            try:
                output.append(byte_str.decode())
            except:
                pass

        return output

    @staticmethod
    def remove_fp_key_candidates(key_candidates, blocklist):

        # There's probably a more "Pythonic" way of doing this

        reduced_key_candidates = []

        for key_candidate in key_candidates:
            if key_candidate not in blocklist:
                reduced_key_candidates.append(key_candidate)

        return reduced_key_candidates


class AESHandler:
    """
    Class to handle AES routines, making use of pycryptodome
    """

    @staticmethod
    def derive_key(key):
        """
        Python 3 adaptation of:
        https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon2016/challenge2-solution.pdf
        """

        key_md5 = hashlib.md5(key.encode()).digest()

        b0 = bytearray()
        for x in key_md5:
            b0.append(x ^ 0x36)

        b1 = bytearray()
        for x in key_md5:
            b1.append(x ^ 0x5C)

        # pad remaining bytes with the appropriate value
        for i in range(0, 64 - len(b0)):
            b0.append(0x36)

        for i in range(0, 64 - len(b1)):
            b1.append(0x5C)

        b0_md5 = hashlib.md5(b0).digest()
        b1_md5 = hashlib.md5(b1).digest()

        return b0_md5 + b1_md5

    @staticmethod
    def AES_CBC_Decrypt(key, data):
        """
        AES CBC decryption method (also unpads decrypted data)
        """
        if len(data) % 16 != 0:
            return 0

        cipher = AES.new(key, AES.MODE_CBC)
        decrypted = unpad(cipher.decrypt(data), AES.block_size)

        return decrypted


class CobaltStrikeShellcodeDecoder(HelperMethods):
    """
    Class to decode the shellcode used in xStart samples to download the next stage Cobalt Strike payload
    """

    # https://github.com/gchq/CyberChef/blob/c9d9730726dfa16a1c5f37024ba9c7ea9f37453d/src/core/operations/RegularExpression.mjs
    ip_regex = b"(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?"

    # https://regexr.com/3au3g
    domain_regex = (
        b"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
    )

    # https://gist.github.com/bpholt/5817999
    http_header_regex = b"([-!#-'*+.0-9A-Z^-z|~]+:.*)\x0D\x0A"

    # https://stackoverflow.com/questions/4669692/valid-characters-for-directory-part-of-a-url-for-short-links
    uri_path_regex = b"(\/[A-Za-z0-9\-/._~!$&'()*+,;=:@%]{3,30})\x00"

    config_filename = "config.json"

    def __init__(self, config_filename="config.json", logger=None):
        self.config_filename = config_filename
        self.logger = logger or logging.getLogger(__name__)

    def parse_config(self, shellcode):
        """
        Parse IPs, domains, HTTP headers, and URI paths out of the decoded shellcode
        """

        config = {}

        raw_parsed_ips = re.findall(self.ip_regex, shellcode)
        raw_parsed_domains = re.findall(self.domain_regex, shellcode)
        raw_parsed_http_headers = re.findall(self.http_header_regex, shellcode)
        raw_parsed_uri_path = re.findall(self.uri_path_regex, shellcode)

        parsed_ips = list(
            set(x for x in self.decode_array_of_byte_strings(raw_parsed_ips))
        )
        parsed_domains = list(
            set(x for x in self.decode_array_of_byte_strings(raw_parsed_domains))
        )
        parsed_http_headers = list(
            set(x for x in self.decode_array_of_byte_strings(raw_parsed_http_headers))
        )
        parsed_uri_path = list(
            set(x for x in self.decode_array_of_byte_strings(raw_parsed_uri_path))
        )

        if parsed_ips:

            self.logger.info("Parsed IPs from shellcode")
            config["ips"] = parsed_ips

            for ip in parsed_ips:
                self.logger.info(ip)

        if parsed_domains:

            self.logger.info("Parsed domains from shellcode")
            config["domains"] = parsed_domains

            for domain in parsed_domains:
                self.logger.info(domain)

        if parsed_http_headers:

            self.logger.info("Parsed HTTP headers from shellcode")
            config["http_headers"] = parsed_http_headers

            for http_header in parsed_http_headers:
                self.logger.info(http_header)

        if parsed_uri_path:

            self.logger.info("Parsed URI path from shellcode")
            config["path"] = parsed_uri_path

            for path in parsed_uri_path:
                self.logger.info(path)

        if config:
            self.logger.info('Saving config to "%s".', self.output_folder)

            with open(
                os.path.join(self.output_folder, self.config_filename), "w"
            ) as outfile:
                json.dump(config, outfile)

        else:
            self.logger.info("No config data parsed from shellcode.")


class xStartConfigExtractor(AESHandler, CobaltStrikeShellcodeDecoder, HelperMethods):
    """
    Class to decode the PE resources of xStart, and to then extract the shellcode's config
    """

    RESOURCE_NAMES = ["MP4", "MKV"]
    KEY_CANDIDATE_BLOCKLIST = ["SeDebugPrivilege"]

    def __init__(self, output_folder, user_key=None, logger=None):
        CobaltStrikeShellcodeDecoder.__init__(self, logger=logger)

        self.output_folder = output_folder
        self.user_key = user_key
        self.logger = logger or logging.getLogger(__name__)

        self.pe = None

    def load_xstart_resources(self):
        """
        Load the PE resources of xStart using pefile

        Reference: http://shelmire.blogspot.com/2014/01/reading-data-from-named-pe-resources.html
        """

        loaded_resources = {}

        for rsrc in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for entry in rsrc.directory.entries:
                if entry.name is not None:
                    if entry.name.__str__() in self.RESOURCE_NAMES:
                        mp4_offset = entry.directory.entries[0].data.struct.OffsetToData
                        mp4_size = entry.directory.entries[0].data.struct.Size

                        loaded_resources[
                            entry.name.__str__()
                        ] = self.pe.get_memory_mapped_image()[
                            mp4_offset : mp4_offset + mp4_size
                        ]

        return loaded_resources

    def load_xstart_resource_key(self):
        """
        Parse the AES key
        """

        for section in self.pe.sections:
            if b".text" in section.Name:
                raw_key_candidates = re.findall(
                    b"\x00([0-9A-Za-z]{16})\x00", section.get_data()
                )

        key_candidates = self.decode_array_of_byte_strings(raw_key_candidates)

        return key_candidates

    def decode_resources(self, loaded_resources, parsed_key):
        """
        Decode the PE resources using the parsed AES key
        """

        decoded_resources = {}

        key = self.derive_key(parsed_key)[:16]

        for name, encoded_resource in loaded_resources.items():
            # A bit hacky, but otherwise the first 16 bytes aren't properly decrypted...
            decoded_resources[name] = self.AES_CBC_Decrypt(
                key,
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                + encoded_resource,
            )[16:]
            # decoded_resources[name] = self.AES_CBC_Decrypt(key, encoded_resource)

        return decoded_resources

    def save_resources(self, decoded_resources):
        """ "
        Save the decoded resources to disk
        """

        if not os.path.isdir(self.output_folder):
            os.mkdir(os.path.join(os.getcwd(), self.output_folder))

        for resource_name, decoded_resource in decoded_resources.items():
            with open(os.path.join(self.output_folder, resource_name), "wb") as outfile:
                outfile.write(decoded_resource)

    def decoder_handler(self, loaded_resources, key):
        """
        Handler routine to decode the resources
        """
        self.logger.debug("Decrypting resources.")
        decoded_resources = self.decode_resources(loaded_resources, key)
        self.logger.debug("Resources decrypted.")

        self.logger.info('Saving decoded resources to "%s".', self.output_folder)
        self.save_resources(decoded_resources)

        if "MP4" in decoded_resources:
            self.parse_config(decoded_resources["MP4"])

        self.logger.info("Decoder finished running!")

    def run(self, filename):
        """
        Main function
        """

        self.logger.debug('Parsing: "%s" ', filename)
        self.pe = pefile.PE(filename)
        self.logger.debug("Parsed PE.")

        self.logger.debug("Loading xStart resources.")
        loaded_resources = self.load_xstart_resources()

        if not loaded_resources:
            self.logger.critical("No xStart resource names found.")

        else:
            self.logger.info("Loaded xStart resources: %s", loaded_resources.keys())

            if self.user_key:
                self.logger.info(
                    "Using user provided AES-128 CBC key: %s", self.user_key
                )
                key_candidates = [self.user_key]

            else:
                self.logger.debug("Parsing AES-128 CBC key.")
                key_candidates = self.load_xstart_resource_key()
                self.logger.debug("Key candidates: %s", key_candidates)
                self.logger.debug("Removing FPs from key candidates.")
                key_candidates = self.remove_fp_key_candidates(
                    key_candidates, self.KEY_CANDIDATE_BLOCKLIST
                )

            if len(key_candidates) > 1:
                self.logger.info("Too many keys parsed.")

                counter = 0
                for key_candidate in key_candidates:
                    print("{} - {}".format(counter, key_candidate))
                    counter += 1

                user_input = input("Which key would you like to use: ")

                try:
                    selected_key = key_candidates[int(user_input)]
                    self.logger.debug("Selected key: %s", selected_key)
                    self.decoder_handler(loaded_resources, selected_key)
                except:
                    self.logger.critical("Failed to select the chosen key.")

            elif len(key_candidates) == 0:
                self.logger.critical("No key candidates found!")

            else:
                parsed_key = key_candidates[0]
                self.logger.info("Parsed AES key: %s", parsed_key)

                self.decoder_handler(loaded_resources, parsed_key)


parser = argparse.ArgumentParser(description=("Auto decode xStart resources"))
parser.add_argument(
    "--input",
    type=str,
    help="the xStart binary to have its resources decoded",
    required=True,
)
parser.add_argument(
    "--output",
    type=str,
    help='(optional) the output folder to save the resources to (default: the SHA256 of the provided input, prepended with "output")',
)
parser.add_argument(
    "--key",
    type=str,
    help="(optional) the AES-128 CBC to use to decode xStart resources",
)
parser.add_argument(
    "--debug",
    action="store_true",
    help="run in debug mode (default:False)",
    default=False,
)

args = parser.parse_args()

logger = logging.getLogger("xstart_config_decoder")
ch = logging.StreamHandler()

if args.debug:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

if args.output:
    output_folder = args.output
else:
    with open(args.input, "rb") as infile:
        output_folder = "output_" + hashlib.sha256(infile.read()).hexdigest()

if args.key:
    user_key = args.key
else:
    user_key = None

resource_decoder = xStartConfigExtractor(
    output_folder, user_key=user_key, logger=logger
)
resource_decoder.run(args.input)
