/ *
Copyright 2021 PwC UK

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

rule wwlib_in_ZIP : Heuristic_and_General {

	meta:
		description = "Detects wwlib.dll filename in a ZIP folder (commonly used by Mustang Panda for DLL hijacking)"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2020-09-16"
		modified_date = "2020-09-16"
		revision = "0"
		hash = "60b33385519592a3ae48bd82767cbc617fd62fb2ee7fed83b4aa6fe3c9d79420"

	strings:
		$ = "wwlib.dll" ascii wide

	condition:
		uint32be(0) == 0x504B0304 and filesize < 2MB and any of them
}

rule wwlib_in_RAR : Heuristic_and_General {

	meta:
		description = "Detects RAR archives that contain a file named 'wwlib.dll'"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2020-12-18"
		modified_date = "2020-12-18"
		revision = "0"
		hash = "34ac6845ab329703d059cb7f8ece73cfe6ebe967a6ac377dab6ca876900be0e4"

	strings:
		$ = "wwlib.dll"

	condition:
		uint32(0) == 0x21726152 and any of them
}

rule xStart_dropper_strings : White_Dev_50 {

	meta:
		description = "Detects the xStart Cobalt Strike dropper via some unique strings"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2020-09-23"
		modified_date = "2020-09-23"
		revision = "0"
		hash = "60b33385519592a3ae48bd82767cbc617fd62fb2ee7fed83b4aa6fe3c9d79420"
		hash = "105b331fe83f56ff154a0006aa267e625653cf70da0747ef14e434767d0d52a6"

	strings:
		$ = "%s --xStart" wide
		$ = {556E69745F41455309556E69745F46756E63}

	condition:
		uint16(0) == 0x5A4D and any of them
}

rule xStart_Crypto_API_Calls : White_Dev_50 {

	meta:
		description = "Detects unique API calls to Windows Crypto routines seen in the xStart Cobalt Strike dropper"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2020-09-23"
		modified_date = "2020-09-23"
		revision = "0"
		hash = "6abdda1579baab9714f4479b616761e25c0c26ff05fd75b56969363ec0315b80"
		hash = "00aa72cf0eedcdcdf48b582160da255c260525f347e2af5cb23a0c328586a2dc"

	strings:
		$crypt_derive_key = {8D 47 0C 50 6A 01 8B 47 08 50 8B 47 10 50 8B 47 04 50 E8 12 FF FF FF}
		$crypt_set_key_param = {6A 00 8D 47 14 50 6A 04 8B 47 0C 50 E8 05 FF FF FF 85 C0}
		$crypt_aquire_context_1 = {68 40 00 00 F0 6A 18 6A 00 6A 00 8D 47 04 50 E8 69 FF FF FF 85 C0}
		$crypt_aquire_content_2 = {6A 08 6A 18 6A 00 6A 00 8D 47 04 50 E8 54 FF FF FF 85 C0}
		$crypt_hash_data = {50 56 8B 47 08 50 E8 33 FF FF FF 85 C0}
		
	condition:
		uint16(0) == 0x5A4D and any of them
}

import "pe"

rule xStart_Resource_Names : White_Dev_50 {

	meta:
		description = "Detects xStart resource names used to store encrypted payloads"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2020-09-23"
		modified_date = "2020-09-23"
		revision = "0"
		hash = "00aa72cf0eedcdcdf48b582160da255c260525f347e2af5cb23a0c328586a2dc"
		hash = "60b33385519592a3ae48bd82767cbc617fd62fb2ee7fed83b4aa6fe3c9d79420"

	condition:
		filesize < 800KB and for 2 resource in pe.resources : (
			resource.name_string == "M\x00K\x00V\x00" or
			resource.name_string == "M\x00P\x004\x00"
		)
}

rule Elysion_Code_Signed_Binaries : White_Dev_50 {

	meta:
		description = "Detects Elysion code signing certificate, observed being used to sign xStart samples"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2020-11-17"
		modified_date = "2020-11-17"
		revision = "0"
		hash = "f9becebb6c9731732d4f5fa04e2946b9f9cdf20f9d15527b549ffffd0e818775"

	strings:
		$serial = {03 D4 33 FD C2 46 9E 9F D8 78 C8 0B C0 54 51 47}
		$name = {ec a3 bc ec 8b 9d ed 9a 8c ec 82 ac 20 ec 97 98 eb a6 ac ec 8b 9c ec 98 a8 eb 9e a9}

	condition:
		uint16(0) == 0x5A4D and any of them
}

rule Eagle_Investments_Code_Signed_Binaries : White_Dev_50 {

	meta:
		description = "Detects Eagle Investments code signing certificate, observed being used to sign xStart samples"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2021-01-13"
		modified_date = "2021-01-13"
		revision = "0"
		hash = "e385d780f22dbda199c0fe7b778d9d7be76c9ced426fbaf81bc9594c4748bc8f"

	strings:
		$serial = {61 6A AE 89 22 BB 78 E2 16 0A 73 05 61 06 B7 BB}
		$name = {45 61 67 6c 65 20 49 6e 76 65 73 74 6d 65 6e 74 20 53 79 73 74 65 6d 73 20 4c 4c 43}

	condition:
		uint16(0) == 0x5A4D and all of them
}

rule xStart_Sender_Email_Address : White_Dev_50 {

	meta:
		description = "Looks for the email address used in White Dev 50 emails used to deliver xStart"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: @BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2020-09-23"
		modified_date = "2020-09-23"
		revision = "0"
		hash = "7096e5e611001ab28892adfd1dbfc2468067f1348c219b896e18afa7e9f874e6"

	strings:
		$ = "gongzhonghao0019@163.com" ascii wide
	
	condition:
		filesize < 2MB and any of them
}