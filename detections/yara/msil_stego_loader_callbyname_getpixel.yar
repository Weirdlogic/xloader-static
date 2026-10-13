import "dotnet"

/*
  .NET steganographic loader seen delivering Formbook (2026-10).
  Report: reports/formbook/2026-10-13-0404070ceb26/report.md
  Reference sample (SHA-256):
    0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26
  Static evidence: rea ev_8ba095c676f6d803bf5199d961c115d3ffd2d6fb2f8a231f68be98694bf56937
*/

rule MSIL_StegoLoader_CallByName_GetPixel
{
    meta:
        description = "Trojanised .NET WinForms app that decodes a payload from bitmap pixels (GetPixel R/G/B) and loads it via VB CallByName(AppDomain, \"Load\") + Activator.CreateInstance"
        author = "Weirdlogic research"
        date = "2026-10-13"
        reference_sha256 = "0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26"
        family = "Formbook (loader stage)"
        confidence = "medium - generic chain; validate against benign VB.NET image apps"

    strings:
        // #Strings heap names (ASCII) used by the loader chain
        $api_callbyname = "CallByName" ascii fullword
        $api_getpixel   = "GetPixel" ascii fullword
        $api_domain     = "get_CurrentDomain" ascii fullword
        $api_gettypes   = "GetTypes" ascii fullword
        $api_create     = "CreateInstance" ascii fullword
        $api_vb         = "Microsoft.VisualBasic" ascii
        // "Load" as a #US (UTF-16) user string: the method name passed to CallByName
        $us_load        = { 09 4C 00 6F 00 61 00 64 00 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and all of ($api_*)
        and $us_load
}

rule MSIL_StegoLoader_Formbook_Builder_Artifacts
{
    meta:
        description = "Builder artefacts of the same crypter: randomised Client\\Temp build path and injected pixel-decoder class names"
        author = "Weirdlogic research"
        date = "2026-10-13"
        reference_sha256 = "0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26"
        confidence = "high for this build; class names may rotate per build"

    strings:
        $pdb      = /\\Desktop\\Client\\Temp\\[A-Za-z]{8,14}\\src\\obj\\(Debug|Release)\\[A-Za-z0-9]{3,10}\.pdb/ ascii
        $cls1     = "IndexerMapExtractor" ascii fullword
        $cls2     = "DecodeChannelAt" ascii fullword
        $cls3     = "ComputeCelestialMechanicsMetrics" ascii fullword

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and ($pdb or 2 of ($cls*))
}

rule MSIL_StegoLoader_InvokeMember_GetPixel
{
    meta:
        description = "Variant 2 of the same pixel loader: payload read via Bitmap.GetPixel and loaded through Type.InvokeMember(\"Load\") on AppDomain, then GetTypes() - no Microsoft.VisualBasic"
        author = "Weirdlogic research"
        date = "2026-10-14"
        reference_sha256 = "9121ef0f2d7b2cc3c887420ecb1eae214db9cb780433d11565ab8c98a6ad99ec"
        confidence = "medium - validated on 50 MalwareBazaar samples (see crosssample/); not yet on a large .NET goodware corpus"

    strings:
        $api_getpixel = "GetPixel" ascii fullword
        $api_invoke   = "InvokeMember" ascii fullword
        $api_gettypes = "GetTypes" ascii fullword
        $api_width    = "get_Width" ascii fullword
        $api_height   = "get_Height" ascii fullword
        $us_load      = { 09 4C 00 6F 00 61 00 64 00 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and all of ($api_*)
        and $us_load
}

rule MSIL_AdvancedSokoban_Carrier_PNG_Geometry
{
    meta:
        description = ".NET PE embedding a PNG whose width-177 == height-225: the carrier image consumed by the 'Advanced Sokoban' stage-2 loader (RestoreOriginalBitmap(img, 177, 225) crops it to a square)"
        author = "Weirdlogic research"
        date = "2026-10-14"
        reference_sha256 = "0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26"
        confidence = "high on 51 MalwareBazaar samples (37/37 carriers, 0 hits without carrier); benign rate on .NET goodware NOT yet measured"

    strings:
        $ihdr = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 }
        // BMP file header + BITMAPINFOHEADER (biSize = 40)
        $bmp  = { 42 4D ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 28 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and dotnet.is_dotnet == 1
        and #ihdr < 64
        and for any i in (1..#ihdr) : (
            uint32be(@ihdr[i] + 16) > 300
            and uint32be(@ihdr[i] + 16) < 4000
            and uint32be(@ihdr[i] + 16) - 177 == uint32be(@ihdr[i] + 20) - 225
        )
        or (
            uint16(0) == 0x5A4D and dotnet.is_dotnet == 1 and #bmp < 64
            and for any j in (1..#bmp) : (
                int32(@bmp[j] + 18) > 300 and int32(@bmp[j] + 18) < 4000
                and int32(@bmp[j] + 18) - 177 == int32(@bmp[j] + 22) - 225
            )
        )
}
