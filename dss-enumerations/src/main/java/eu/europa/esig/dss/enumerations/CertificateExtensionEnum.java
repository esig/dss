/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.enumerations;

/**
 * Contains enumeration of certificate extensions supported by the application
 *
 */
public enum CertificateExtensionEnum implements OidDescription {

    /**
     * 4.2.1.1. Authority Key Identifier.
     * id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
     * AuthorityKeyIdentifier ::= SEQUENCE {
     *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
     *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
     *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
     */
    AUTHORITY_KEY_IDENTIFIER("authorityKeyIdentifier", "2.5.29.35"),

    /**
     * 4.2.1.2. Subject Key Identifier
     * id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
     * SubjectKeyIdentifier ::= KeyIdentifier
     */
    SUBJECT_KEY_IDENTIFIER("subjectKeyIdentifier", "2.5.29.14"),

    /**
     * 4.2.1.3. Key Usage
     * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
     * KeyUsage ::= BIT STRING
     */
    KEY_USAGE("keyUsage", "2.5.29.15"),

    /**
     * RFC 3280. 4.2.1.4 Private Key Usage Period (deprecated)
     * id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }
     * PrivateKeyUsagePeriod ::= SEQUENCE {
     *      notBefore       [0]     GeneralizedTime OPTIONAL,
     *      notAfter        [1]     GeneralizedTime OPTIONAL }
     */
    PRIVATE_KEY_USAGE_PERIOD("privateKeyUsagePeriod", "2.5.29.16"),

    /**
     * 4.2.1.4. Certificate Policies
     * id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
     * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
     */
    CERTIFICATE_POLICIES("certificatePolicies", "2.5.29.32"),

    /**
     * 4.2.1.5. Policy Mappings
     * id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 }
     * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
     *      issuerDomainPolicy      CertPolicyId,
     *      subjectDomainPolicy     CertPolicyId }
     */
    POLICY_MAPPINGS("policyMappings", "2.5.29.33"),

    /**
     * 4.2.1.6. Subject Alternative Name
     * id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
     * SubjectAltName ::= GeneralNames
     */
    SUBJECT_ALTERNATIVE_NAME("subjectAlternativeName", "2.5.29.17"),

    /**
     * 4.2.1.7. Issuer Alternative Name
     * id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 }
     * IssuerAltName ::= GeneralNames
     */
    ISSUER_ALTERNATIVE_NAME("issuerAlternativeName", "2.5.29.18"),

    /**
     * 4.2.1.8. Subject Directory Attributes
     * id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }
     * SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
     */
    SUBJECT_DIRECTORY_ATTRIBUTES("subjectDirectoryAttributes", "2.5.29.9"),

    /**
     * 4.2.1.9. Basic Constraints
     * id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
     * BasicConstraints ::= SEQUENCE {
     *      cA                      BOOLEAN DEFAULT FALSE,
     *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */
    BASIC_CONSTRAINTS("basicConstraints", "2.5.29.19"),

    /**
     * 4.2.1.10. Name Constraints
     * id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
     * NameConstraints ::= SEQUENCE {
     *      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
     *      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
     */
    NAME_CONSTRAINTS("nameConstraints", "2.5.29.30"),

    /**
     * 4.2.1.11. Policy Constraints
     * id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
     * PolicyConstraints ::= SEQUENCE {
     *      requireExplicitPolicy           [0] SkipCerts OPTIONAL,
     *      inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
     */
    POLICY_CONSTRAINTS("policyConstraints", "2.5.29.36"),

    /**
     * 4.2.1.12. Extended Key Usage
     * anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
     * id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
     */
    EXTENDED_KEY_USAGE("extendedKeyUsage", "2.5.29.37"),

    /**
     * 4.2.1.13. CRL Distribution Points
     * id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
     * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
     */
    CRL_DISTRIBUTION_POINTS("CRLDistributionPoints", "2.5.29.31"),

    /**
     * 4.2.1.14. Inhibit anyPolicy
     * id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
     * InhibitAnyPolicy ::= SkipCerts
     */
    INHIBIT_ANY_POLICY("inhibitAnyPolicy", "2.5.29.54"),

    /**
     * 4.2.1.15. Freshest CRL (a.k.a. Delta CRL Distribution Point)
     * id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }
     * FreshestCRL ::= CRLDistributionPoints
     */
    FRESHEST_CRL("freshestCRL", "2.5.29.46"),

    /**
     * 4.2.2.1. Authority Information Access
     * id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
     * AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
     */
    AUTHORITY_INFORMATION_ACCESS("authorityInfoAccess", "1.3.6.1.5.5.7.1.1"),

    /**
     * 4.2.2.2. Subject Information Access
     * id-pe-subjectInfoAccess OBJECT IDENTIFIER ::= { id-pe 11 }
     * SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
     */
    SUBJECT_INFORMATION_ACCESS("subjectInfoAccess", "1.3.6.1.5.5.7.1.11"),

    /**
     * RFC 6960. 4.2.2.2.1. Revocation Checking of an Authorized Responder
     * id-pkix-ocsp-nocheck OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
     * ext-ocsp-nocheck EXTENSION ::= { SYNTAX NULL IDENTIFIED BY id-pkix-ocsp-nocheck }
     */
    OCSP_NOCHECK("id_pkix_ocsp_nocheck", "1.3.6.1.5.5.7.48.1.5"),

    /**
     * ETSI EN 319 412-1
     * id-etsi-ext-valassured-ST-certs OBJECT IDENTIFIER ::= { id-etsi-ext 1 }
     * ext-etsi-valassured-ST-certs EXTENSION ::= { SYNTAX NULL IDENTIFIED BY id-etsi-ext-valassured-ST-certs }
     */
    VALIDITY_ASSURED_SHORT_TERM("id_etsi_ext_valassured_ST_certs", "0.4.0.194121.2.1"),

    /**
     * RFC 3739. 3.2.5. Biometric Information
     * id-pe-biometricInfo OBJECT IDENTIFIER  ::= {id-pe 2}
     * BiometricSyntax ::= SEQUENCE OF BiometricData
     */
    BIOMETRIC_INFORMATION("biometricInfo", "1.3.6.1.5.5.7.1.2"),

    /**
     * RFC 3739. 3.2.6. Qualified Certificate Statements
     * id-pe-qcStatements OBJECT IDENTIFIER ::= { id-pe 3 }
     * QCStatements ::= SEQUENCE OF QCStatement
     */
    QC_STATEMENTS("QCStatements", "1.3.6.1.5.5.7.1.3");

    private final String description;
    private final String oid;

    CertificateExtensionEnum(String description, String oid) {
        this.description = description;
        this.oid = oid;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public String getOid() {
        return oid;
    }

    /**
     * Returns a {@code CertificateExtensionEnum} if an enum with the given OID exists
     *
     * @param oid {@link String} to get {@link CertificateExtensionEnum} for
     * @return {@link CertificateExtensionEnum} if enum is found, FALSE otherwise
     */
    public static CertificateExtensionEnum forOid(String oid) {
        for (CertificateExtensionEnum value : values()) {
            if (oid.equals(value.oid)) {
                return value;
            }
        }
        return null;
    }

}
