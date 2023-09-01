package eu.europa.esig.dss.pki.jaxb.service;


import eu.europa.esig.dss.pki.jaxb.XmlDigestAlgo;
import eu.europa.esig.dss.pki.jaxb.utils.PKIUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class X509CertBuilder {

    private static final JcaX509ExtensionUtils EXT_UTILS;

    static {
        try {
            EXT_UTILS = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private XmlDigestAlgo digestAlgo;

    private boolean ca;

    private boolean ocspNoCheck;

    private X500Name issuerName;

    private X500Name subjectName;

    private PrivateKey issuerKey;

    private PublicKey publicKey;

    private KeyUsage keyUsage;

    private CertificatePolicies certificatePolicies;

    private ASN1Sequence qcStatementIds;

    private List<KeyPurposeId> keyPurposeIds;

    private String aiaUrl;

    private String ocspUrl;

    private String crlUrl;

    private boolean pss;

    public X509CertBuilder() {
    }

    public X509CertBuilder subject(X500Name subjectName, PublicKey subjectPublicKey) {
        this.subjectName = subjectName;
        this.publicKey = subjectPublicKey;
        return this;
    }

    public X509CertBuilder issuer(X500Name issuerName, PrivateKey issuerPrivateKey) {
        this.issuerName = issuerName;
        this.issuerKey = issuerPrivateKey;
        return this;
    }

    public X509CertBuilder keyUsage(KeyUsage keyUsage) {
        this.keyUsage = keyUsage;
        return this;
    }

    public X509CertBuilder certificatePolicies(CertificatePolicies certificatePolicies) {
        this.certificatePolicies = certificatePolicies;
        return this;
    }

    public X509CertBuilder qcStatementIds(ASN1Sequence qcStatementIds) {
        this.qcStatementIds = qcStatementIds;
        return this;
    }

    public X509CertBuilder ca() {
        this.ca = true;
        return this;
    }

    public X509CertBuilder digestAlgo(XmlDigestAlgo digestAlgo) {
        this.digestAlgo = digestAlgo;
        return this;
    }

    public X509CertBuilder ocspNoCheck() {
        this.ocspNoCheck = true;
        return this;
    }

    public X509CertBuilder ocspSigningExtension() {
        return extendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning);
    }

    public X509CertBuilder timestamping() {
        return extendedKeyUsage(KeyPurposeId.id_kp_timeStamping);
    }

    public X509CertBuilder extendedKeyUsage(KeyPurposeId purposeId) {
        if (keyPurposeIds == null) {
            keyPurposeIds = new ArrayList<>();
        }
        keyPurposeIds.add(purposeId);
        return this;
    }

    public X509CertBuilder crl(String crlUrl) {
        this.crlUrl = crlUrl;
        return this;
    }

    public X509CertBuilder ocsp(String ocspUrl) {
        this.ocspUrl = ocspUrl;
        return this;
    }

    public X509CertBuilder aia(String aiaUrl) {
        this.aiaUrl = aiaUrl;
        return this;
    }

    public X509CertBuilder pss(boolean pss) {
        this.pss = pss;
        return this;
    }

    public X509CertificateHolder build(BigInteger serial, Date notBefore, Date notAfter) throws Exception {

        String signatureAlgo = PKIUtils.getAlgorithmString(issuerKey.getAlgorithm(), digestAlgo, pss);

        ContentSigner rootSigner = new JcaContentSignerBuilder(signatureAlgo).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);

        SubjectPublicKeyInfo membersKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, membersKeyInfo);

        if (keyUsage != null) {
            addKeyUsageExtension(certBuilder);
        }

        if (certificatePolicies != null) {
            addCertificatePolicies(certBuilder);
        }

        if (qcStatementIds != null) {
            addQCStatementIds(certBuilder);
        }

        if (keyPurposeIds != null) {
            addExtendedKeyUsageExtension(certBuilder, buildExtendedKeyUsage(keyPurposeIds));
        }

        if (crlUrl != null) {
            addCRLExtension(certBuilder);
        }

        if (ocspUrl != null || aiaUrl != null) {
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

    private KeyPurposeId[] buildExtendedKeyUsage(List<KeyPurposeId> purposeIds) {
        return keyPurposeIds.toArray(new KeyPurposeId[keyPurposeIds.size()]);
    }

    private void addKeyUsageExtension(X509v3CertificateBuilder certBuilder) throws CertIOException {
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
    }

    private void addExtendedKeyUsageExtension(X509v3CertificateBuilder certBuilder, KeyPurposeId[] usages) throws CertIOException {
        ExtendedKeyUsage extKeyUsage = new ExtendedKeyUsage(usages);
        certBuilder.addExtension(Extension.extendedKeyUsage, true, extKeyUsage);
    }

    private void addCertificatePolicies(X509v3CertificateBuilder certBuilder) throws CertIOException {
        certBuilder.addExtension(Extension.certificatePolicies, true, certificatePolicies);
    }

    private void addQCStatementIds(X509v3CertificateBuilder certBuilder) throws CertIOException {
        certBuilder.addExtension(Extension.qCStatements, false, qcStatementIds);
    }

    private void addAIAExtension(X509v3CertificateBuilder certBuilder) throws CertIOException {
        List<AccessDescription> access = new ArrayList<>();

        if (ocspUrl != null) {
            GeneralName location = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
            access.add(new AccessDescription(AccessDescription.id_ad_ocsp, location));
        }

        if (aiaUrl != null) {
            GeneralName location = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(aiaUrl));
            access.add(new AccessDescription(AccessDescription.id_ad_caIssuers, location));
        }

        if (access.size() > 1) {
            AccessDescription[] array = access.toArray(new AccessDescription[access.size()]);
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

    private void addSKI(X509v3CertificateBuilder certBuilder) throws CertIOException, GeneralSecurityException {
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, EXT_UTILS.createSubjectKeyIdentifier(publicKey));
    }

    private void addBasicConstraint(X509v3CertificateBuilder certBuilder) throws CertIOException {
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    }

    private void addOCSPNoCheck(X509v3CertificateBuilder certBuilder) throws IOException {
        certBuilder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE);
    }

}