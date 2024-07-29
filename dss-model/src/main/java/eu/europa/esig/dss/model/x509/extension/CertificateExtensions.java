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
package eu.europa.esig.dss.model.x509.extension;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * This class contains a set of certificate extensions processed by the application
 *
 */
public class CertificateExtensions implements Serializable {

    private static final long serialVersionUID = 1192565195947571006L;

    /** RFC 5280: 4.2.1.3. Key Usage */
    private KeyUsage keyUsage;

    /** RFC 5280: 4.2.1.4. Certificate Policies */
    private CertificatePolicies certificatePolicies;

    /** RFC 5280: 4.2.1.6. Subject Alternative Name */
    private SubjectAlternativeNames subjectAlternativeNames;

    /** RFC 5280: 4.2.1.9. Basic Constraints */
    private BasicConstraints basicConstraints;

    /** RFC 5280: 4.2.1.10. Name Constraints */
    private NameConstraints nameConstraints;

    /** RFC 5280: 4.2.1.11. Policy Constraints */
    private PolicyConstraints policyConstraints;

    /** RFC 5280: 4.2.1.12. Extended Key Usage */
    private ExtendedKeyUsages extendedKeyUsage;

    /** RFC 5280: 4.2.1.13. CRL Distribution Points */
    private CRLDistributionPoints crlDistributionPoints;

    /** RFC 5280: 4.2.1.14. Inhibit anyPolicy */
    private InhibitAnyPolicy inhibitAnyPolicy;

    /** RFC 5280: 4.2.1.15. Freshest CRL (a.k.a. Delta CRL Distribution Point) */
    private FreshestCRL freshestCRL;

    /** RFC 5280: 4.2.1.1. Authority Key Identifier */
    private AuthorityKeyIdentifier authorityKeyIdentifier;

    /** RFC 5280: 4.2.1.2. Subject Key Identifier */
    private SubjectKeyIdentifier subjectKeyIdentifier;

    /** RFC 5280: 4.2.2.1. Authority Information Access */
    private AuthorityInformationAccess authorityInformationAccess;

    /** RFC 6960: 4.2.2.2.1. Revocation Checking of an Authorized Responder */
    private OCSPNoCheck ocspNoCheck;

    /** ETSI EN 319 412-1: 5.2.2 Validity Assured - Short Term */
    private ValidityAssuredShortTerm validityAssuredShortTerm;

    /** RFC 9608: No Revocation Available for X.509 Public Key Certificates */
    private NoRevAvail noRevAvail;

    /** ETSI EN 319 412-1/5: QCStatements */
    private QcStatements qcStatements;

    /** List of other extensions */
    private final List<CertificateExtension> otherExtensions = new ArrayList<>();

    /** List of all certificate extensions */
    private final List<CertificateExtension> allExtensions = new ArrayList<>();

    /**
     * Default constructor
     */
    public CertificateExtensions() {
        // empty
    }

    /**
     * Returns the key usage
     *
     * @return {@link KeyUsage}
     */
    public KeyUsage getKeyUsage() {
        return keyUsage;
    }

    /**
     * Sets the key usage
     *
     * @param keyUsage {@link KeyUsage}
     */
    public void setKeyUsage(KeyUsage keyUsage) {
        this.keyUsage = keyUsage;
        addToAllExtensionsList(keyUsage);
    }

    /**
     * Returns the certificate policies
     *
     * @return {@link CertificatePolicies}
     */
    public CertificatePolicies getCertificatePolicies() {
        return certificatePolicies;
    }

    /**
     * Sets the certificate policies
     *
     * @param certificatePolicies {@link CertificatePolicies}
     */
    public void setCertificatePolicies(CertificatePolicies certificatePolicies) {
        this.certificatePolicies = certificatePolicies;
        addToAllExtensionsList(certificatePolicies);
    }

    /**
     * Returns the subject alternative names
     *
     * @return {@link SubjectAlternativeNames}
     */
    public SubjectAlternativeNames getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    /**
     * Sets the subject alternative names
     *
     * @param subjectAlternativeNames {@link SubjectAlternativeNames}
     */
    public void setSubjectAlternativeNames(SubjectAlternativeNames subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
        addToAllExtensionsList(subjectAlternativeNames);
    }

    /**
     * Returns the basic constraints
     *
     * @return {@link BasicConstraints}
     */
    public BasicConstraints getBasicConstraints() {
        return basicConstraints;
    }

    /**
     * Sets the basic constraints
     *
     * @param basicConstraints {@link BasicConstraints}
     */
    public void setBasicConstraints(BasicConstraints basicConstraints) {
        this.basicConstraints = basicConstraints;
        addToAllExtensionsList(basicConstraints);
    }

    /**
     * Returns the name constraints
     *
     * @return {@link NameConstraints}
     */
    public NameConstraints getNameConstraints() {
        return nameConstraints;
    }

    /**
     * Sets the name constraints
     *
     * @param nameConstraints {@link NameConstraints}
     */
    public void setNameConstraints(NameConstraints nameConstraints) {
        this.nameConstraints = nameConstraints;
        addToAllExtensionsList(nameConstraints);
    }

    /**
     * Returns the policy constraints
     *
     * @return {@link PolicyConstraints}
     */
    public PolicyConstraints getPolicyConstraints() {
        return policyConstraints;
    }

    /**
     * Sets the policy constrains
     *
     * @param policyConstraints {@link PolicyConstraints}
     */
    public void setPolicyConstraints(PolicyConstraints policyConstraints) {
        this.policyConstraints = policyConstraints;
        addToAllExtensionsList(policyConstraints);
    }

    /**
     * Returns the extended key usages
     *
     * @return {@link ExtendedKeyUsages}
     */
    public ExtendedKeyUsages getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    /**
     * Gets the extended key usages
     *
     * @param extendedKeyUsage {@link ExtendedKeyUsages}
     */
    public void setExtendedKeyUsage(ExtendedKeyUsages extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
        addToAllExtensionsList(extendedKeyUsage);
    }

    /**
     * Returns the CRL distribution points
     *
     * @return {@link CRLDistributionPoints}
     */
    public CRLDistributionPoints getCRLDistributionPoints() {
        return crlDistributionPoints;
    }

    /**
     * Sets the CRL distribution points
     *
     * @param crlDistributionPoints {@link CRLDistributionPoints}
     */
    public void setCRLDistributionPoints(CRLDistributionPoints crlDistributionPoints) {
        this.crlDistributionPoints = crlDistributionPoints;
        addToAllExtensionsList(crlDistributionPoints);
    }

    /**
     * Returns the InhibitAnyPolicy extension
     *
     * @return {@link InhibitAnyPolicy}
     */
    public InhibitAnyPolicy getInhibitAnyPolicy() {
        return inhibitAnyPolicy;
    }

    /**
     * Sets the InhibitAnyPolicy extension
     *
     * @param inhibitAnyPolicy {@link InhibitAnyPolicy}
     */
    public void setInhibitAnyPolicy(InhibitAnyPolicy inhibitAnyPolicy) {
        this.inhibitAnyPolicy = inhibitAnyPolicy;
        addToAllExtensionsList(inhibitAnyPolicy);
    }

    /**
     * Returns the FreshestCRL extension
     *
     * @return {@link FreshestCRL}
     */
    public FreshestCRL getFreshestCRL() {
        return freshestCRL;
    }

    /**
     * Sets the FreshestCRL extension
     *
     * @param freshestCRL {@link FreshestCRL}
     */
    public void setFreshestCRL(FreshestCRL freshestCRL) {
        this.freshestCRL = freshestCRL;
        addToAllExtensionsList(freshestCRL);
    }

    /**
     * Returns the authority key identifier
     *
     * @return {@link AuthorityKeyIdentifier}
     */
    public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    /**
     * Sets the authority key identifier
     *
     * @param authorityKeyIdentifier {@link AuthorityKeyIdentifier}
     */
    public void setAuthorityKeyIdentifier(AuthorityKeyIdentifier authorityKeyIdentifier) {
        this.authorityKeyIdentifier = authorityKeyIdentifier;
        addToAllExtensionsList(authorityKeyIdentifier);
    }

    /**
     * Returns the subject key identifier
     *
     * @return {@link SubjectKeyIdentifier}
     */
    public SubjectKeyIdentifier getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    /**
     * Sets the subject key identifier
     *
     * @param subjectKeyIdentifier {@link SubjectKeyIdentifier}
     */
    public void setSubjectKeyIdentifier(SubjectKeyIdentifier subjectKeyIdentifier) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        addToAllExtensionsList(subjectKeyIdentifier);
    }

    /**
     * Returns the authority information access
     *
     * @return {@link AuthorityInformationAccess}
     */
    public AuthorityInformationAccess getAuthorityInformationAccess() {
        return authorityInformationAccess;
    }

    /**
     * Sets the authority information access
     *
     * @param authorityInformationAccess {@link AuthorityInformationAccess}
     */
    public void setAuthorityInformationAccess(AuthorityInformationAccess authorityInformationAccess) {
        this.authorityInformationAccess = authorityInformationAccess;
        addToAllExtensionsList(authorityInformationAccess);
    }

    /**
     * Returns the ocsp-nocheck value
     *
     * @return {@link OCSPNoCheck}
     */
    public OCSPNoCheck getOcspNoCheck() {
        return ocspNoCheck;
    }

    /**
     * Sets the ocsp-nocheck value
     *
     * @param ocspNoCheck {@link OCSPNoCheck}
     */
    public void setOcspNoCheck(OCSPNoCheck ocspNoCheck) {
        this.ocspNoCheck = ocspNoCheck;
        addToAllExtensionsList(ocspNoCheck);
    }

    /**
     * Returns the ext-etsi-valassured-ST-certs value
     *
     * @return {@link ValidityAssuredShortTerm}
     */
    public ValidityAssuredShortTerm getValidityAssuredShortTerm() {
        return validityAssuredShortTerm;
    }

    /**
     * Sets the ext-etsi-valassured-ST-certs value
     *
     * @param validityAssuredShortTerm {@link ValidityAssuredShortTerm}
     */
    public void setValidityAssuredShortTerm(ValidityAssuredShortTerm validityAssuredShortTerm) {
        this.validityAssuredShortTerm = validityAssuredShortTerm;
        addToAllExtensionsList(validityAssuredShortTerm);
    }

    /**
     * Returns the noRevAvail value
     *
     * @return {@link NoRevAvail}
     */
    public NoRevAvail getNoRevAvail() {
        return noRevAvail;
    }

    /**
     * Sets the noRevAvail value
     *
     * @param noRevAvail {@link NoRevAvail}
     */
    public void setNoRevAvail(NoRevAvail noRevAvail) {
        this.noRevAvail = noRevAvail;
        addToAllExtensionsList(noRevAvail);
    }

    /**
     * Returns the QcStatements
     *
     * @return {@link QcStatements}
     */
    public QcStatements getQcStatements() {
        return qcStatements;
    }

    /**
     * Sets the QcStatements
     *
     * @param qcStatements {@link QcStatements}
     */
    public void setQcStatements(QcStatements qcStatements) {
        this.qcStatements = qcStatements;
        addToAllExtensionsList(qcStatements);
    }

    /**
     * Returns a list of other certificate extensions
     *
     * @return a list of other {@link CertificateExtension}
     */
    public List<CertificateExtension> getOtherExtensions() {
        return otherExtensions;
    }

    /**
     * Adds another certificate extension
     *
     * @param certificateExtension {@link CertificateExtension} to add
     */
    public void addOtherExtension(CertificateExtension certificateExtension) {
        this.otherExtensions.add(certificateExtension);
        addToAllExtensionsList(certificateExtension);
    }

    /**
     * Returns a list of all certificate extensions
     *
     * @return a list of {@link CertificateExtension}s
     */
    public List<CertificateExtension> getAllCertificateExtensions() {
        return allExtensions;
    }

    private void addToAllExtensionsList(CertificateExtension certificateExtension) {
        if (certificateExtension != null) {
            this.allExtensions.add(certificateExtension);
        }
    }

}
