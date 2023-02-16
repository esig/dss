package eu.europa.esig.dss.model.x509.extension;

import java.util.ArrayList;
import java.util.List;

/**
 * This class contains a set of certificate extensions processed by the application
 *
 */
public class CertificateExtensions {

    /** RFC 5280: 4.2.1.3. Key Usage */
    private KeyUsage keyUsage;

    /** RFC 5280: 4.2.1.4. Certificate Policies */
    private CertificatePolicies certificatePolicies;

    /** RFC 5280: 4.2.1.6. Subject Alternative Name */
    private SubjectAlternativeNames subjectAlternativeNames;

    /** RFC 5280: 4.2.1.9. Basic Constraints */
    private BasicConstraints basicConstraints;

    /** RFC 5280: 4.2.1.11. Policy Constraints */
    private PolicyConstraints policyConstraints;

    /** RFC 5280: 4.2.1.12. Extended Key Usage */
    private ExtendedKeyUsages extendedKeyUsage;

    /** RFC 5280: 4.2.1.13. CRL Distribution Points */
    private CRLDistributionPoints crlDistributionPoints;

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

    /** ETSI EN 319 412-1/5: QCStatements */
    private QcStatements qcStatements;

    /** List of other extensions */
    private List<CertificateExtension> otherExtensions = new ArrayList<>();

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
    }

}
