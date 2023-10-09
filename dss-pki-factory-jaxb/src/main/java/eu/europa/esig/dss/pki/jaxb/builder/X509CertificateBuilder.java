package eu.europa.esig.dss.pki.jaxb.builder;


import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Builds a {@code X509CertificateHolder}
 *
 */
public class X509CertificateBuilder {

    /** The certificate's subject DN */
    private X500Name subjectName;

    /** Certificate's public key */
    private PublicKey publicKey;

    /** The certificate's issuer DN */
    private X500Name issuerName;

    /** Key used to sign the certificate */
    private PrivateKey issuerKey;

    /** SignatureAlgorithm used to sign this certificate */
    private SignatureAlgorithm signatureAlgorithm;

    /** Whether this certificate is a CA certificate */
    private boolean ca;

    /** The key usages */
    private List<KeyUsageBit> keyUsages;

    /** List of extended key usages */
    private List<String> extendedKeyUsages;

    /** AIA.caIssuers Url */
    private String caIssuersUrl;

    /** OCSP Url */
    private String ocspUrl;

    /** CRL Url */
    private String crlUrl;

    /** The list of certificate policies */
    private List<String> certificatePolicies;

    /** List of QcStatements */
    private List<String> qcStatements;

    /** List of QcTypes */
    private List<String> qcTypes;

    /** List of QcCClegislations */
    private List<String> qcCClegislations;

    /** Whether the ocsp-no-check extension should be present */
    private boolean ocspNoCheck;

    /**
     * Default constructor to create an empty instance of X509CertificateBuilder.
     * Methods {@code #subject} and {@code issuer} shall be called at minimum to create a {@code X509CertificateHolder}
     */
    public X509CertificateBuilder() {
        // empty
    }

    /**
     * Sets mandatory information about the certificate
     *
     * @param subjectName {@link X500Name} representing a DN subject name of the certificate to be created
     * @param subjectPublicKey {@link PublicKey} of the certificate to be created
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder subject(X500Name subjectName, PublicKey subjectPublicKey) {
        this.subjectName = subjectName;
        this.publicKey = subjectPublicKey;
        return this;
    }

    /**
     * Sets mandatory information about the certificate's issuer to sign the created certificate
     *
     * @param issuerName {@link X500Name} representing a DN issuer name of the certificate to be created
     * @param issuerPrivateKey {@link PrivateKey} of the issuer certificate to sign the certificate
     * @param signatureAlgorithm {@link SignatureAlgorithm} to be used on signature creation
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder issuer(X500Name issuerName, PrivateKey issuerPrivateKey, SignatureAlgorithm signatureAlgorithm) {
        this.issuerName = issuerName;
        this.issuerKey = issuerPrivateKey;
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Sets the key usages for the certificate
     *
     * @param keyUsages a list of {@link KeyUsageBit}s
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder keyUsages(List<KeyUsageBit> keyUsages) {
        this.keyUsages = keyUsages;
        return this;
    }

    /**
     * Sets the certificate policies for the certificate
     *
     * @param certificatePolicies a list of {@link String} certificate policy identifiers
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder certificatePolicies(List<String> certificatePolicies) {
        this.certificatePolicies = certificatePolicies;
        return this;
    }

    /**
     * Sets the QcStatement Ids
     *
     * @param qcStatements a list of {@link String} qcStatement identifiers
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder qcStatements(List<String> qcStatements) {
        this.qcStatements = qcStatements;
        return this;
    }

    /**
     * Sets the QcType Ids
     *
     * @param qcTypes a list of {@link String} qcType identifiers
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder qcTypes(List<String> qcTypes) {
        this.qcTypes = qcTypes;
        return this;
    }

    /**
     * Sets the QcCCLegislation Ids
     *
     * @param qcCClegislations a list of {@link String} qcCCLegislation identifiers
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder qcCClegislations(List<String> qcCClegislations) {
        this.qcCClegislations = qcCClegislations;
        return this;
    }

    /**
     * Sets whether the certificate is a CA certificate
     *
     * @param ca whether the certificate is a CA certificate
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder ca(boolean ca) {
        this.ca = ca;
        return this;
    }

    /**
     * Sets whether the ocsp-no-check extension shall be present
     *
     * @param ocspNoCheck whether the ocsp-no-check extension shall be present
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder ocspNoCheck(boolean ocspNoCheck) {
        this.ocspNoCheck = ocspNoCheck;
        return this;
    }

    /**
     * Adds extended key usages certificate extension
     *
     * @param extendedKeyUsages a list of {@link String} OIDs
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder extendedKeyUsages(List<String> extendedKeyUsages) {
        this.extendedKeyUsages = extendedKeyUsages;
        return this;
    }

    /**
     * Sets the CRL distribution point URL
     *
     * @param crlUrl {@link String}
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder crl(String crlUrl) {
        this.crlUrl = crlUrl;
        return this;
    }

    /**
     * Sets the OCSP access point URL
     *
     * @param ocspUrl {@link String}
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder ocsp(String ocspUrl) {
        this.ocspUrl = ocspUrl;
        return this;
    }

    /**
     * Sets the AIA CA Issuers distribution point URL
     *
     * @param caIssuersUrl {@link String}
     * @return {@link X509CertificateBuilder} this
     */
    public X509CertificateBuilder caIssuers(String caIssuersUrl) {
        this.caIssuersUrl = caIssuersUrl;
        return this;
    }

    /**
     * Builds a certificate token
     *
     * @param serial {@link BigInteger} serial number
     * @param notBefore {@link Date} the certificate's start validity date
     * @param notAfter {@link Date} the certificate's end validity date
     * @return {@link X509CertificateHolder}
     * @throws OperatorCreationException if an error on certificate signing occurs
     * @throws IOException if an error on certificate's content creation occurs
     */
    public X509CertificateHolder build(BigInteger serial, Date notBefore, Date notAfter) throws OperatorCreationException, IOException {
        ContentSigner rootSigner = new JcaContentSignerBuilder(signatureAlgorithm.getJCEId()).build(issuerKey);

        SubjectPublicKeyInfo membersKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, membersKeyInfo);

        if (keyUsages != null) {
            addKeyUsageExtension(certBuilder);
        }

        if (certificatePolicies != null) {
            addCertificatePolicies(certBuilder);
        }

        if (qcStatements != null || qcTypes != null || qcCClegislations != null) {
            addQCStatementIds(certBuilder);
        }

        if (extendedKeyUsages != null) {
            addExtendedKeyUsageExtension(certBuilder);
        }

        if (crlUrl != null) {
            addCRLExtension(certBuilder);
        }

        if (ocspUrl != null || caIssuersUrl != null) {
            addAIAExtension(certBuilder);
        }

        addSKI(certBuilder);

        if (ca) {
            addBasicConstraint(certBuilder);
        }

        if (ocspNoCheck) {
            addOCSPNoCheck(certBuilder);
        }

        return certBuilder.build(rootSigner);
    }

    private void addKeyUsageExtension(X509v3CertificateBuilder certBuilder) throws CertIOException {
        int keyUsage = 0;
        for (KeyUsageBit keyUsageBit : keyUsages) {
            keyUsage = keyUsage | keyUsageBit.getBit();
        }
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
    }

    private void addExtendedKeyUsageExtension(X509v3CertificateBuilder certBuilder) throws CertIOException {
        KeyPurposeId[] keyPurposeIds = extendedKeyUsages.stream().map(e ->
                KeyPurposeId.getInstance(new ASN1ObjectIdentifier(e))).toArray(KeyPurposeId[]::new);
        org.bouncycastle.asn1.x509.ExtendedKeyUsage bcExtendedKeyUsage = new org.bouncycastle.asn1.x509.ExtendedKeyUsage(keyPurposeIds);
        certBuilder.addExtension(Extension.extendedKeyUsage, true, bcExtendedKeyUsage);
    }

    private void addCertificatePolicies(X509v3CertificateBuilder certBuilder) throws CertIOException {
        if (Utils.isCollectionNotEmpty(certificatePolicies)) {
            PolicyInformation[] policyInformation = new PolicyInformation[Utils.collectionSize(certificatePolicies)];
            int index = 0;
            for (String certificatePolicyEntry : certificatePolicies) {
                policyInformation[index] = new PolicyInformation(getPolicyOid(certificatePolicyEntry));
                index = index + 1;
            }
            certBuilder.addExtension(Extension.certificatePolicies, true, new CertificatePolicies(policyInformation));
        }
    }

    /**
     * Get CertificatePolicies OID from enum or return entry params if no match found
     *
     * @param policy {@link String}
     * @return {@link ASN1ObjectIdentifier}
     */
    private ASN1ObjectIdentifier getPolicyOid(String policy) {
        try {
            CertificatePolicy oid = CertificatePolicy.valueOf(policy.toUpperCase());
            return new ASN1ObjectIdentifier(oid.getOid());
        } catch (IllegalArgumentException e) {
            return new ASN1ObjectIdentifier(policy);
        }
    }

    private void addQCStatementIds(X509v3CertificateBuilder certBuilder) throws CertIOException {
        if (Utils.isCollectionNotEmpty(qcStatements) || Utils.isCollectionNotEmpty(qcTypes) || Utils.isCollectionNotEmpty(qcCClegislations)) {
            certBuilder.addExtension(Extension.qCStatements, false, getQCStatementsIds());
        }
    }

    private ASN1Sequence getQCStatementsIds() {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        // QC Statements IDs
        if (Utils.isCollectionNotEmpty(qcStatements)) {
            for (String qcStatement : qcStatements) {
                vector.add(new DERSequence(getQcStatementOid(qcStatement)));
            }
        }

        // QC Types
        if (Utils.isCollectionNotEmpty(qcTypes)) {
            ASN1EncodableVector typeVector = new ASN1EncodableVector();
            for (String qcTypes : qcTypes) {
                typeVector.add(getQcTypeOid(qcTypes));
            }

            QCStatement qcTypes = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, new DERSequence(typeVector));
            vector.add(qcTypes);
        }

        // QC CClegislation
        if (Utils.isCollectionNotEmpty(qcCClegislations)) {
            ASN1EncodableVector cclegislationVector = new ASN1EncodableVector();
            for (String qcCClegislation : qcCClegislations) {
                cclegislationVector.add(new DERPrintableString(qcCClegislation));
            }

            QCStatement qcCClegislation = new QCStatement(OID.id_etsi_qcs_QcCClegislation, new DERSequence(cclegislationVector));

            vector.add(qcCClegislation);
        }

        return new DERSequence(vector);
    }

    /**
     * Get QCStatements OID from enum or return entry params if no match found
     *
     * @param qcString {@link String}
     * @return {@link ASN1ObjectIdentifier}
     */
    private ASN1ObjectIdentifier getQcStatementOid(String qcString) {
        eu.europa.esig.dss.enumerations.QCStatement qcStatement = eu.europa.esig.dss.enumerations.QCStatement.forLabel(qcString);
        if (qcStatement == null) {
            qcStatement = eu.europa.esig.dss.enumerations.QCStatement.forOID(qcString);
        }
        if (qcStatement == null) {
            qcStatement = eu.europa.esig.dss.enumerations.QCStatement.valueOf(qcString.toUpperCase());
        }
        if (qcStatement != null) {
            return new ASN1ObjectIdentifier(qcStatement.getOid());
        }
        // not supported OID
        return new ASN1ObjectIdentifier(qcString);
    }

    /**
     * Get QcType OID from enum or return entry params if no match found
     *
     * @param qcString {@link String}
     * @return {@link ASN1ObjectIdentifier}
     */
    private ASN1ObjectIdentifier getQcTypeOid(String qcString) {
        QCType qcType = QCTypeEnum.forLabel(qcString);
        if (qcType == null) {
            qcType = QCType.fromOid(qcString);
        }
        return new ASN1ObjectIdentifier(qcType.getOid());
    }

    private void addAIAExtension(X509v3CertificateBuilder certBuilder) throws CertIOException {
        List<AccessDescription> access = new ArrayList<>();

        if (ocspUrl != null) {
            GeneralName location = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
            access.add(new AccessDescription(AccessDescription.id_ad_ocsp, location));
        }

        if (caIssuersUrl != null) {
            GeneralName location = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(caIssuersUrl));
            access.add(new AccessDescription(AccessDescription.id_ad_caIssuers, location));
        }

        if (access.size() > 1) {
            AccessDescription[] array = access.toArray(new AccessDescription[0]);
            certBuilder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(array));
        } else {
            certBuilder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(access.get(0)));
        }
    }

    private void addCRLExtension(X509v3CertificateBuilder certBuilder) throws CertIOException {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl));
        GeneralNames gns = GeneralNames.getInstance(new DERSequence(gn));
        DistributionPointName dpn = new DistributionPointName(DistributionPointName.FULL_NAME, gns);
        DistributionPoint distp = new DistributionPoint(dpn, null, null);

        certBuilder.addExtension(Extension.cRLDistributionPoints, false, new DERSequence(distp));
    }

    private void addSKI(X509v3CertificateBuilder certBuilder) throws CertIOException {
        byte[] skiValue = DSSASN1Utils.computeSkiFromCertPublicKey(publicKey);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(skiValue));
    }

    private void addBasicConstraint(X509v3CertificateBuilder certBuilder) throws CertIOException {
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    }

    private void addOCSPNoCheck(X509v3CertificateBuilder certBuilder) throws IOException {
        certBuilder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE);
    }

}