#pragma once
#include <map>
#include <cstring>
using namespace std;

static const string dictionary =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static map<string, string> string_map = {
        {"1.2.840.10045.2.1", "EC Public Key:"},
        {"1.3.6.1.5.5.7.1.1", "AuthorityInfoAccess:"},
        {"1.3.6.1.5.5.7.3.2", "id_kp_clientAuth: True"},
        {"1.3.6.1.5.5.7.3.1", "id_kp_serverAuth: True"},
        {"1.3.6.1.5.5.7.3.2", "id_kp_clientAuth: True"},
        {"2.5.29.19", "Basic Constraints:"},
        {"2.23.140.1.2.2", "organization-validated:"},
        {"2.5.29.37", "Extended key usage:"},
        {"2.5.29.31", "CRL Distribution Points:"},
        {"Extension", "Extend:"}};
        
    static map<string, string> hexMap = {
        {"1.2.840.10045.3.1.7",
         "SEC 2 recommended elliptic curve domain: "},
        {"2.5.29.35", "Authority Key Identifier: "},
        {"2.5.29.14", "Subject Key Identifier: "}};
    static map<string, string> OID_map = {
        {"1.3.6.1.5.5.7.2.1", "OID for CPS qualifier: "},
        {"1.3.6.1.5.5.7.48.1", "OCSP: "},
        {"1.3.6.1.5.5.7.48.2", "id-ad-caIssuers: "},
        {"1.3.6.1.4.1.311.60.2.1.1", "Locality: "},
        {"1.3.6.1.4.1.311.60.2.1.3", "Country: "},
        {"1.3.6.1.4.1.311.60.2.1.2", "State or province: "},
        {"2.5.4.3", "id-at-commonName: "},
        {"2.5.4.5", "id-at-serialNumber: "},
        {"2.5.4.6", "id-at-countryName: "},
        {"2.5.4.7", "id-at-localityName: "},
        {"2.5.4.8", "id-at-stateOrProvinceName: "},
        {"2.5.4.9", "id-at-streetAddress: "},
        {"2.5.4.10", "id-at-organizationName: "},
        {"2.5.4.11", "id-at-organizationalUnitName: "},
        {"2.5.4.12", "id-at-tag: "},
        {"2.5.4.13", "id-at-description: "},
        {"2.5.4.15", "id-at-businessCategory: "},
        {"2.5.29.32", "Certificate Policies: "},
        {"2.5.29.15", "Key Usage: "}};

    static map<string, string> algorithmMap = {
        {"1.2.840.10040.4.1", "DSA"},
        {"1.2.840.10040.4.3", "sha1DSA"},
        {"1.2.840.113549.1.1.1", "RSA"},
        {"1.2.840.113549.1.1.2", "md2RSA"},
        {"1.2.840.113549.1.1.3", "md4RSA"},
        {"1.2.840.113549.1.1.4", "md5RSA"},
        {"1.2.840.113549.1.1.5", "sha1RSA"},
        {"1.3.14.3.2.29", "sha1RSA"},
        {"1.2.840.113549.1.1.13", "sha512RSA"},
        {"1.2.840.113549.1.1.11", "sha256RSA"}};

    static map<string, string> SubjectAlternativeName={
        {"2.5.29.17", "Subject Alternative Name"}
    };