package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.AuthorityInformationAccess;
import eu.europa.esig.dss.model.x509.extension.AuthorityKeyIdentifier;
import eu.europa.esig.dss.model.x509.extension.BasicConstraints;
import eu.europa.esig.dss.model.x509.extension.CRLDistributionPoints;
import eu.europa.esig.dss.model.x509.extension.CertificateExtension;
import eu.europa.esig.dss.model.x509.extension.CertificateExtensions;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicies;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicy;
import eu.europa.esig.dss.model.x509.extension.ExtendedKeyUsages;
import eu.europa.esig.dss.model.x509.extension.KeyUsage;
import eu.europa.esig.dss.model.x509.extension.OCSPNoCheck;
import eu.europa.esig.dss.model.x509.extension.QcStatements;
import eu.europa.esig.dss.model.x509.extension.SubjectAlternativeNames;
import eu.europa.esig.dss.model.x509.extension.SubjectKeyIdentifier;
import eu.europa.esig.dss.model.x509.extension.ValidityAssuredShortTerm;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * This class contains utility methods for extraction certificate extension (whether critical or not)
 *
 */
public class CertificateExtensionsUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateExtensionsUtils.class);

    /**
     * This method extracts the certificate extensions from the given {@code certificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get certificate extension from
     * @return {@link CertificateExtensions}
     */
    public static CertificateExtensions getCertificateExtensions(CertificateToken certificateToken) {
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        setCertificateExtensions(certificateExtensions, certificateToken, certificateToken.getCertificate().getCriticalExtensionOIDs());
        setCertificateExtensions(certificateExtensions, certificateToken, certificateToken.getCertificate().getNonCriticalExtensionOIDs());
        return certificateExtensions;
    }

    private static void setCertificateExtensions(CertificateExtensions certificateExtensions,
                                                 CertificateToken certificateToken, Collection<String> extensionOIDs) {
        if (Utils.isCollectionNotEmpty(extensionOIDs)) {
            for (String oid : extensionOIDs) {
                if (isSubjectAlternativeNames(oid)) {
                    certificateExtensions.setSubjectAlternativeNames(getSubjectAlternativeNames(certificateToken));
                } else if (isAuthorityKeyIdentifier(oid)) {
                    certificateExtensions.setAuthorityKeyIdentifier(getAuthorityKeyIdentifier(certificateToken));
                } else if (isSubjectKeyIdentifier(oid)) {
                    certificateExtensions.setSubjectKeyIdentifier(getSubjectKeyIdentifier(certificateToken));
                } else if (isAuthorityInformationAccess(oid)) {
                    certificateExtensions.setAuthorityInformationAccess(getAuthorityInformationAccess(certificateToken));
                } else if (isCRLDistributionPoints(oid)) {
                    certificateExtensions.setCRLDistributionPoints(getCRLDistributionPoints(certificateToken));
                } else if (isBasicConstraints(oid)) {
                    certificateExtensions.setBasicConstraints(getBasicConstraints(certificateToken));
                } else if (isKeyUsage(oid)) {
                    certificateExtensions.setKeyUsage(getKeyUsage(certificateToken));
                } else if (isExtendedKeyUsage(oid)) {
                    certificateExtensions.setExtendedKeyUsage(getExtendedKeyUsage(certificateToken));
                } else if (isCertificatePolicies(oid)) {
                    certificateExtensions.setCertificatePolicies(getCertificatePolicies(certificateToken));
                } else if (isOcspNoCheck(oid)) {
                    certificateExtensions.setOcspNoCheck(getOcspNoCheck(certificateToken));
                } else if (isValidityAssuredShortTerm(oid)) {
                    certificateExtensions.setValidityAssuredShortTerm(getValAssuredSTCerts(certificateToken));
                } else if (isQcStatements(oid)) {
                    certificateExtensions.setQcStatements(getQcStatements(certificateToken));
                } else {
                    certificateExtensions.addOtherExtension(getOtherCertificateExtension(certificateToken, oid));
                }
            }
        }
    }

    /**
     * This method verifies whether {@code oid} corresponds to the subject alternative names extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the subject alternative names extension OID, FALSE otherwise
     */
    public static boolean isSubjectAlternativeNames(String oid) {
        return CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the authority key identifier extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the authority key identifier extension OID, FALSE otherwise
     */
    public static boolean isAuthorityKeyIdentifier(String oid) {
        return CertificateExtensionEnum.AUTHORITY_KEY_IDENTIFIER.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the subject key identifier extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the subject key identifier extension OID, FALSE otherwise
     */
    public static boolean isSubjectKeyIdentifier(String oid) {
        return CertificateExtensionEnum.SUBJECT_KEY_IDENTIFIER.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the authority information access extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the authority information access extension OID, FALSE otherwise
     */
    public static boolean isAuthorityInformationAccess(String oid) {
        return CertificateExtensionEnum.AUTHORITY_INFORMATION_ACCESS.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the CRL distribution points extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the CRL distribution points extension OID, FALSE otherwise
     */
    public static boolean isCRLDistributionPoints(String oid) {
        return CertificateExtensionEnum.CRL_DISTRIBUTION_POINTS.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the basic constraints extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the basic constraints extension OID, FALSE otherwise
     */
    public static boolean isBasicConstraints(String oid) {
        return CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the key usage extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the key usage extension OID, FALSE otherwise
     */
    public static boolean isKeyUsage(String oid) {
        return CertificateExtensionEnum.KEY_USAGE.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the extended key usage extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the extended key usage extension OID, FALSE otherwise
     */
    public static boolean isExtendedKeyUsage(String oid) {
        return CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the certificate policies extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the certificate policies extension OID, FALSE otherwise
     */
    public static boolean isCertificatePolicies(String oid) {
        return CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the ocsp-nocheck extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the ocsp-nocheck extension OID, FALSE otherwise
     */
    public static boolean isOcspNoCheck(String oid) {
        return CertificateExtensionEnum.OCSP_NOCHECK.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the ext-etsi-valassured-ST-certs extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the ext-etsi-valassured-ST-certs extension OID, FALSE otherwise
     */
    public static boolean isValidityAssuredShortTerm(String oid) {
        return CertificateExtensionEnum.VALIDITY_ASSURED_SHORT_TERM.getOid().equals(oid);
    }

    /**
     * This method verifies whether {@code oid} corresponds to the qc-statements extension OID
     *
     * @param oid {@link String}
     * @return TRUE if OID corresponds to the qc-statements extension OID, FALSE otherwise
     */
    public static boolean isQcStatements(String oid) {
        return CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(oid);
    }

    /**
     * Returns a subject alternative names, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link SubjectAlternativeNames}
     */
    public static SubjectAlternativeNames getSubjectAlternativeNames(CertificateToken certificateToken) {
        try {
            final SubjectAlternativeNames subjectAlternateNames = new SubjectAlternativeNames();
            subjectAlternateNames.setOctets(certificateToken.getCertificate().getExtensionValue(subjectAlternateNames.getOid()));

            final List<String> result = new ArrayList<>();
            Collection<List<?>> subjectAlternativeNames = certificateToken.getCertificate().getSubjectAlternativeNames();
            if (Utils.isCollectionNotEmpty(subjectAlternativeNames)) {
                for (List<?> list : subjectAlternativeNames) {
                    // type + value
                    if (Utils.collectionSize(list) == 2) {
                        Object value = list.get(1);
                        if (value instanceof String) {
                            result.add((String) value);
                        } else {
                            LOG.trace("Ignored value : {}", value);
                        }
                    }
                }
            }
            subjectAlternateNames.setNames(result);
            subjectAlternateNames.checkCritical(certificateToken);
            return subjectAlternateNames;

        } catch (Exception e) {
            LOG.warn("Unable to extract SubjectAlternativeNames", e);
            return null;
        }
    }

    /**
     * Returns the authority information access, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link AuthorityInformationAccess}
     */
    public static AuthorityInformationAccess getAuthorityInformationAccess(CertificateToken certificateToken) {
        final byte[] authInfoAccessExtensionValue = certificateToken.getCertificate()
                .getExtensionValue(CertificateExtensionEnum.AUTHORITY_INFORMATION_ACCESS.getOid());
        if (Utils.isArrayEmpty(authInfoAccessExtensionValue)) {
            return null;
        }

        try {
            ASN1Sequence asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(authInfoAccessExtensionValue);
            if (asn1Sequence == null || asn1Sequence.size() == 0) {
                LOG.warn("Empty ASN1Sequence for AuthorityInformationAccess");
                return null;
            }

            final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
            authorityInformationAccess.setOctets(authInfoAccessExtensionValue);

            org.bouncycastle.asn1.x509.AuthorityInformationAccess aia = org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(asn1Sequence);
            AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
            authorityInformationAccess.setCaIssuers(getAccessUrls(accessDescriptions, X509ObjectIdentifiers.id_ad_caIssuers));
            authorityInformationAccess.setOcsp(getAccessUrls(accessDescriptions, X509ObjectIdentifiers.id_ad_ocsp));
            authorityInformationAccess.checkCritical(certificateToken);
            return authorityInformationAccess;

        } catch (Exception e) {
            LOG.error("Unable to parse authorityInfoAccess", e);
            return null;
        }
    }

    private static List<String> getAccessUrls(AccessDescription[] accessDescriptions, ASN1ObjectIdentifier aiaOid) {
        final List<String> locationsUrls = new ArrayList<>();
        for (AccessDescription accessDescription : accessDescriptions) {
            if (aiaOid.equals(accessDescription.getAccessMethod())) {
                GeneralName gn = accessDescription.getAccessLocation();
                String location = parseGn(gn);
                if (location != null) {
                    locationsUrls.add(location);
                }
            }
        }
        return locationsUrls;
    }

    /**
     * Returns the CA issuers URIs extracted from authorityInfoAccess.caIssuers field
     *
     * @param certificate {@link CertificateToken}
     * @return a list of CA issuers URIs, or empty list if the extension is not present.
     */
    public static List<String> getCAIssuersAccessUrls(final CertificateToken certificate) {
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(certificate);
        return aia != null ? aia.getCaIssuers() : Collections.emptyList();
    }

    /**
     * Returns the OCSP URIs extracted from authorityInfoAccess.ocsp field
     *
     * @param certificate {@link CertificateToken}
     * @return a list of OCSP URIs, or empty list if the extension is not present.
     */
    public static List<String> getOCSPAccessUrls(final CertificateToken certificate) {
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(certificate);
        return aia != null ? aia.getOcsp() : Collections.emptyList();
    }

    /**
     * Returns the subject key identifier, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link SubjectKeyIdentifier}
     */
    public static AuthorityKeyIdentifier getAuthorityKeyIdentifier(CertificateToken certificateToken) {
        byte[] extensionValue = certificateToken.getCertificate().getExtensionValue(CertificateExtensionEnum.AUTHORITY_KEY_IDENTIFIER.getOid());
        if (Utils.isArrayEmpty(extensionValue)) {
            return null;
        }

        try {
            final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
            authorityKeyIdentifier.setOctets(extensionValue);

            ASN1Primitive extension = JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
            org.bouncycastle.asn1.x509.AuthorityKeyIdentifier aki = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier.getInstance(extension);
            authorityKeyIdentifier.setKeyIdentifier(aki.getKeyIdentifier());
            if (aki.getAuthorityCertIssuer() != null && aki.getAuthorityCertSerialNumber() != null) {
                IssuerSerial issuerSerial = new IssuerSerial(aki.getAuthorityCertIssuer(), aki.getAuthorityCertSerialNumber());
                authorityKeyIdentifier.setAuthorityCertIssuerSerial(DSSASN1Utils.getDEREncoded(issuerSerial));
            }
            authorityKeyIdentifier.checkCritical(certificateToken);
            return authorityKeyIdentifier;

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to retrieve authority key identifier of a certificate. " +
                    "Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Returns the subject key identifier, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link SubjectKeyIdentifier}
     */
    public static SubjectKeyIdentifier getSubjectKeyIdentifier(CertificateToken certificateToken) {
        byte[] extensionValue = certificateToken.getCertificate().getExtensionValue(CertificateExtensionEnum.SUBJECT_KEY_IDENTIFIER.getOid());
        if (Utils.isArrayEmpty(extensionValue)) {
            return null;
        }

        try {
            final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
            subjectKeyIdentifier.setOctets(extensionValue);

            ASN1Primitive extension = JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
            org.bouncycastle.asn1.x509.SubjectKeyIdentifier skiBC = org.bouncycastle.asn1.x509.SubjectKeyIdentifier.getInstance(extension);
            subjectKeyIdentifier.setSki(skiBC.getKeyIdentifier());
            subjectKeyIdentifier.checkCritical(certificateToken);
            return subjectKeyIdentifier;

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to retrieve subject key identifier of a certificate. " +
                    "Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Returns the CRL distribution points, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link CRLDistributionPoints}
     */
    public static CRLDistributionPoints getCRLDistributionPoints(CertificateToken certificateToken) {
        final byte[] crlDistributionPointsBytes = certificateToken.getCertificate().getExtensionValue(CertificateExtensionEnum.CRL_DISTRIBUTION_POINTS.getOid());
        if (crlDistributionPointsBytes != null) {
            try {
                final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
                crlDistributionPoints.setOctets(crlDistributionPointsBytes);

                final List<String> urls = new ArrayList<>();
                final ASN1Sequence asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(crlDistributionPointsBytes);
                final CRLDistPoint distPoint = CRLDistPoint.getInstance(asn1Sequence);
                final DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
                for (final DistributionPoint distributionPoint : distributionPoints) {

                    final DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
                    if (DistributionPointName.FULL_NAME != distributionPointName.getType()) {
                        continue;
                    }

                    final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
                    final GeneralName[] names = generalNames.getNames();
                    for (final GeneralName name : names) {
                        String location = parseGn(name);
                        if (location != null) {
                            urls.add(location);
                        }
                    }
                }

                crlDistributionPoints.setCrlUrls(urls);
                crlDistributionPoints.checkCritical(certificateToken);
                return crlDistributionPoints;

            } catch (Exception e) {
                LOG.error("Unable to parse cRLDistributionPoints", e);
            }
        }
        return null;
    }

    private static String parseGn(GeneralName gn) {
        try {
            if (GeneralName.uniformResourceIdentifier == gn.getTagNo()) {
                ASN1String str = (ASN1String) ((DERTaggedObject) gn.toASN1Primitive()).getBaseObject();
                return str.getString();
            }
        } catch (Exception e) {
            LOG.warn("Unable to parse GN '{}'", gn, e);
        }
        return null;
    }

    /**
     * Returns the CRL distribution URIs extracted from cRLDistributionPoints field
     *
     * @param certificate {@link CertificateToken}
     * @return a list of CA issuers URIs, or empty list if the extension is not present.
     */
    public static List<String> getCRLAccessUrls(final CertificateToken certificate) {
        CRLDistributionPoints crlDistributionPoints = CertificateExtensionsUtils.getCRLDistributionPoints(certificate);
        return crlDistributionPoints != null ? crlDistributionPoints.getCrlUrls() : Collections.emptyList();
    }

    /**
     * Returns a basic constraints extension, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link BasicConstraints}
     */
    public static BasicConstraints getBasicConstraints(CertificateToken certificateToken) {
        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setOctets(certificateToken.getCertificate().getExtensionValue(basicConstraints.getOid()));

        final int value = certificateToken.getCertificate().getBasicConstraints();
        basicConstraints.setCa(value != -1);
        basicConstraints.setPathLenConstraint(value);
        basicConstraints.checkCritical(certificateToken);
        return basicConstraints;
    }

    /**
     * Returns the key usage, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link KeyUsage}
     */
    public static KeyUsage getKeyUsage(CertificateToken certificateToken) {
        final boolean[] keyUsageArray = certificateToken.getCertificate().getKeyUsage();
        if (keyUsageArray != null) {
            final KeyUsage keyUsage = new KeyUsage();
            keyUsage.setOctets(certificateToken.getCertificate().getExtensionValue(keyUsage.getOid()));

            final List<KeyUsageBit> keyUsageBits = new ArrayList<>();
            for (KeyUsageBit keyUsageBit : KeyUsageBit.values()) {
                if (keyUsageArray[keyUsageBit.getIndex()]) {
                    keyUsageBits.add(keyUsageBit);
                }
            }
            keyUsage.setKeyUsageBits(keyUsageBits);
            keyUsage.checkCritical(certificateToken);
            return keyUsage;
        }
        return null;
    }

    /**
     * Returns the extended key usage, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link ExtendedKeyUsages}
     */
    public static ExtendedKeyUsages getExtendedKeyUsage(CertificateToken certificateToken) {
        try {
            final ExtendedKeyUsages extendedKeyUsage = new ExtendedKeyUsages();
            extendedKeyUsage.setOctets(certificateToken.getCertificate().getExtensionValue(extendedKeyUsage.getOid()));
            extendedKeyUsage.setOids(certificateToken.getCertificate().getExtendedKeyUsage());
            extendedKeyUsage.checkCritical(certificateToken);
            return extendedKeyUsage;

        } catch (CertificateParsingException e) {
            LOG.warn("Unable to retrieve ExtendedKeyUsage : {}", e.getMessage());
            return null;
        }
    }

    /**
     * Returns the certificate policies, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link CertificatePolicies}
     */
    public static CertificatePolicies getCertificatePolicies(CertificateToken certificateToken) {
        final byte[] certificatePoliciesBinaries = certificateToken.getCertificate()
                .getExtensionValue(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        if (Utils.isArrayNotEmpty(certificatePoliciesBinaries)) {
            final CertificatePolicies certificatePolicies = new CertificatePolicies();
            certificatePolicies.setOctets(certificatePoliciesBinaries);

            final List<CertificatePolicy> policiesList = new ArrayList<>();
            try {
                ASN1Sequence seq = DSSASN1Utils.getAsn1SequenceFromDerOctetString(certificatePoliciesBinaries);
                for (int ii = 0; ii < seq.size(); ii++) {
                    CertificatePolicy cp = new CertificatePolicy();
                    final PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(ii));
                    cp.setOid(policyInfo.getPolicyIdentifier().getId());
                    ASN1Sequence policyQualifiersSeq = policyInfo.getPolicyQualifiers();
                    if (policyQualifiersSeq != null) {
                        for (int jj = 0; jj < policyQualifiersSeq.size(); jj++) {
                            PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(policyQualifiersSeq.getObjectAt(jj));
                            if (PolicyQualifierId.id_qt_cps.equals(pqi.getPolicyQualifierId())) {
                                cp.setCpsUrl(DSSASN1Utils.getString(pqi.getQualifier()));
                            }
                        }
                    }
                    policiesList.add(cp);
                }
                certificatePolicies.setPolicyList(policiesList);
                certificatePolicies.checkCritical(certificateToken);
                return certificatePolicies;

            } catch (Exception e) {
                LOG.warn("Unable to parse the certificatePolicies extension '{}' : {}", Utils.toBase64(certificatePoliciesBinaries), e.getMessage(), e);
            }
        }
        return null;
    }

    /**
     * Returns the ocsp-nocheck extension value, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link OCSPNoCheck}
     */
    public static OCSPNoCheck getOcspNoCheck(CertificateToken certificateToken) {
        final byte[] extensionValue = certificateToken.getCertificate().getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
        if (extensionValue != null) {
            final OCSPNoCheck ocspNoCheck = new OCSPNoCheck();
            ocspNoCheck.setOctets(extensionValue);
            ocspNoCheck.setOcspNoCheck(isNullIdentifiedValuePresent(extensionValue));
            ocspNoCheck.checkCritical(certificateToken);
            return ocspNoCheck;
        }
        return null;
    }

    /**
     * Checks if the certificate contains ocsp-nocheck extension indicating if the revocation data
     * should be checked for an OCSP signing certificate.<br>
     * <a href="https://www.rfc-editor.org/rfc/rfc6960">RFC 6960</a><br>
     *
     * @param certificateToken
     *            the certificate to be checked
     * @return true if the certificate has the id_pkix_ocsp_nocheck extension
     */
    public static boolean hasOcspNoCheckExtension(CertificateToken certificateToken) {
        OCSPNoCheck ocspNoCheck = getOcspNoCheck(certificateToken);
        return ocspNoCheck != null && ocspNoCheck.isOcspNoCheck();
    }

    /**
     * Returns the ext-etsi-valassured-ST-certs extension value, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link ValidityAssuredShortTerm}
     */
    public static ValidityAssuredShortTerm getValAssuredSTCerts(CertificateToken certificateToken) {
        final byte[] extensionValue = certificateToken.getCertificate().getExtensionValue(OID.id_etsi_ext_valassured_ST_certs.getId());
        if (extensionValue != null) {
            final ValidityAssuredShortTerm validityAssuredShortTerm = new ValidityAssuredShortTerm();
            validityAssuredShortTerm.setOctets(extensionValue);
            validityAssuredShortTerm.setValAssuredSTCerts(isNullIdentifiedValuePresent(extensionValue));
            validityAssuredShortTerm.checkCritical(certificateToken);
            return validityAssuredShortTerm;
        }
        return null;
    }

    private static boolean isNullIdentifiedValuePresent(final byte[] extensionValue) {
        try {
            final ASN1Primitive derObject = DSSASN1Utils.toASN1Primitive(extensionValue);
            if (derObject instanceof DEROctetString) {
                return DSSASN1Utils.isDEROctetStringNull((DEROctetString) derObject);
            }

        } catch (Exception e) {
            LOG.debug("Exception when processing 'id_pkix_ocsp_no_check'", e);
        }
        return false;
    }

    /**
     * Checks if the certificate contains ext-etsi-valassured-ST-certs extension indicating
     * that the validity of the certificate is assured because the certificate is a "short-term certificate".
     * That is, the time as indicated in the certificate attribute from notBefore through notAfter,
     * inclusive, is shorter than the maximum time to process a revocation request as specified by
     * the certificate practice statement or certificate policy.
     */
    public static boolean hasValAssuredShortTermCertsExtension(CertificateToken certificateToken) {
        ValidityAssuredShortTerm valAssuredSTCerts = getValAssuredSTCerts(certificateToken);
        return valAssuredSTCerts != null && valAssuredSTCerts.isValAssuredSTCerts();
    }

    /**
     * Returns the qc-statements extension value, when present
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link QcStatements}
     */
    public static QcStatements getQcStatements(CertificateToken certificateToken) {
        final QcStatements qcStatements = QcStatementUtils.getQcStatements(certificateToken);
        if (qcStatements != null) {
            qcStatements.checkCritical(certificateToken);
        }
        return qcStatements;
    }

    /**
     * Returns a certificate extension for an unsupported OID
     *
     * @param certificateToken {@link CertificateToken}
     * @param oid {@link String} of the found certificate extension
     * @return {@link CertificateExtension}
     */
    private static CertificateExtension getOtherCertificateExtension(CertificateToken certificateToken, String oid) {
        CertificateExtension certificateExtension;
        CertificateExtensionEnum value = CertificateExtensionEnum.forOid(oid);
        if (value != null) {
            certificateExtension = new CertificateExtension(value);
        } else {
            LOG.warn("Not supported CertificateExtension with OID : '{}'", oid);
            certificateExtension = new CertificateExtension(oid);
        }
        certificateExtension.setOctets(certificateToken.getCertificate().getExtensionValue(oid));
        certificateExtension.checkCritical(certificateToken);
        return certificateExtension;
    }

}
