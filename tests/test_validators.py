import inspect

import pytest

from depii import validators as v


@pytest.mark.parametrize(
    ("check", "good", "bad"),
    [
        (v.luhn, "4111 1111 1111 1111", "4111 1111 1111 1112"),
        (v.verhoeff, "2363", "2364"),
        (v.credit_card, "5500-0000-0000-0004", "1234 5678 9012 3456"),
        (v.iban, "DE89 3704 0044 0532 0130 00", "DE89 3704 0044 0532 0130 01"),
        (v.iban, "GB29NWBK60161331926819", "GB29NWBK6016133192681"),
        (v.bic, "DEUTDEFF", "DEUTXXFF"),
        (v.aba_routing, "021000021", "021000022"),
        (v.base58check, "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "1BoatSLRHtKNngkdXEeobR76b53LETtpyU"),
        (
            v.bech32,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        ),
        (v.ipv6, "2001:db8::8a2e:370:7334", "12:30:45"),
        (v.geo_coordinates, "48.8584,2.2945", "98.8584,2.2945"),
        (v.vin_check_digit, "1HGCM82633A004352", "1HGCM82643A004352"),
        (v.us_ssn, "078-05-1120", "666-05-1120"),
        (v.us_ssn, "123-45-6789", "900-45-6789"),
        (v.in_aadhaar, "2345 6789 0124", "2345 6789 0123"),
        (v.in_gstin, "27AAPFU0939F1ZV", "27AAPFU0939F1ZW"),
        (v.gb_nino, "AB123456C", "GB123456C"),
        (v.gb_nhs, "943 476 5919", "943 476 5918"),
        (v.de_tax_id, "86095742719", "86095742710"),
        (v.es_dni, "12345678Z", "12345678A"),
        (v.es_nie, "X1234567L", "X1234567A"),
        (v.it_fiscal_code, "RSSMRA80A01H501U", "RSSMRA80A01H501A"),
        (v.nl_bsn, "111222333", "111222334"),
        # added in 0.2; the valid values are published sample numbers
        (v.ca_sin, "130 692 544", "130 692 545"),
        (v.au_tfn, "123 456 782", "123 456 783"),
        (v.au_abn, "51 824 753 556", "51 824 753 557"),
        (v.au_medicare, "2123 45670 1", "2123 45671 1"),
        (v.nz_ird, "49-091-850", "49-091-851"),
        (v.nz_nhi, "ZZZ0016", "ZZZ0017"),
        (v.br_cpf, "529.982.247-25", "529.982.247-26"),
        (v.br_cnpj, "11.222.333/0001-81", "11.222.333/0001-82"),
        (v.cl_rut, "12.345.678-5", "12.345.678-K"),
        (v.ar_cuit, "20-12345678-6", "20-12345678-7"),
        (v.sg_nric, "S1234567D", "S1234567E"),
        (v.jp_my_number, "123456789018", "123456789019"),
        (v.kr_rrn, "900101-1234567", "901301-1234567"),
        (v.cn_resident_id, "11010519491231002X", "110105194912310021"),
        (v.pl_pesel, "44051401359", "44051401358"),
        (v.pl_nip, "123-456-32-18", "123-456-32-19"),
        (v.pl_id_card, "ABA300000", "ABA300001"),
        (v.se_personnummer, "811228-9874", "811228-9875"),
        (v.dk_cpr, "010190-1234", "320190-1234"),
        (v.fi_hetu, "131052-308T", "131052-308U"),
        (v.be_national_number, "85.07.30-033.28", "85.07.30-033.29"),
        (v.pt_nif, "123456789", "123456788"),
        (v.ie_ppsn, "1234567T", "1234567U"),
        (v.at_svnr, "1237 010180", "1238 010180"),
        (v.ch_ahv, "756.9217.0769.85", "756.9217.0769.86"),
        (v.no_fnr, "01010750160", "01010750161"),
        (v.tr_tckn, "10000000146", "10000000147"),
        (v.za_id, "8001015009087", "8001015009088"),
        (v.ae_emirates_id, "784-1968-6570305-0", "784-1968-6570305-1"),
    ],
)
def test_check_digits(check, good, bad):
    assert check(good)
    assert not check(bad)


def test_fr_nir_key_and_corsica():
    body = "1850578006084"
    assert v.fr_nir(f"{body}{97 - int(body) % 97:02d}")
    assert not v.fr_nir(f"{body}{(97 - int(body) % 97 + 1) % 100:02d}")
    corsica = "185052A006084"
    key = 97 - int(corsica.replace("2A", "19")) % 97
    assert v.fr_nir(f"{corsica}{key:02d}")


def test_de_tax_id_needs_one_repeated_digit():
    # check digit is right, but no digit repeats in the first ten
    assert not v.de_tax_id("12345678903")


# Every public bool validator, so a new one is covered without being listed here.
ALL_VALIDATORS = [
    function
    for name, function in vars(v).items()
    if inspect.isfunction(function)
    and function.__module__ == v.__name__
    and not name.startswith("_")
    and name not in {"digits_of", "alnum_of"}
]


def test_validator_list_is_complete():
    assert len(ALL_VALIDATORS) > 50


@pytest.mark.parametrize("check", ALL_VALIDATORS, ids=lambda f: f.__name__)
@pytest.mark.parametrize(
    "junk", ["", " ", "x", "0", "-", "é", "1" * 400, "A" * 400, "\x00", "0" * 18, "Ñ" * 18]
)
def test_validators_never_raise(check, junk):
    assert check(junk) in (True, False)
