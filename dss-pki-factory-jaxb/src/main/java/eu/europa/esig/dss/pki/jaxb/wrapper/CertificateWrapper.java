package eu.europa.esig.dss.pki.jaxb.wrapper;

import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.pki.jaxb.XmlCRLType;
import eu.europa.esig.dss.pki.jaxb.XmlCertificateType;
import eu.europa.esig.dss.pki.jaxb.XmlDateDefinitionType;
import eu.europa.esig.dss.pki.jaxb.XmlDigestAlgo;
import eu.europa.esig.dss.pki.jaxb.XmlEntityKey;
import eu.europa.esig.dss.pki.jaxb.XmlKeyAlgo;
import eu.europa.esig.dss.pki.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.pki.jaxb.dto.CertificatePolicyOids;
import eu.europa.esig.dss.pki.jaxb.dto.QCStatementOids;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class CertificateWrapper {

    private final XmlCertificateType cert;
    private final EntityId key;

    public CertificateWrapper(XmlCertificateType cert, String issuerName) {
        this.cert = cert;
        this.key = new EntityId(issuerName, cert.getSerialNumber());
    }

    public Long getSerialNumber() {
        return cert.getSerialNumber();
    }

    public EntityId getKey() {
        return key;
    }

    public boolean isCA() {
        return cert.getCa() != null;
    }

    public boolean isTSA() {
        return cert.getTsa() != null;
    }

    public boolean isOcspNoCheck() {
        return cert.getOcspNoCheck() != null;
    }

    public boolean isOcspSigning() {
        return cert.getOcspSigning() != null;
    }

    public boolean isTrustAnchor() {
        return cert.getTrustAnchor() != null;
    }

    public boolean isToBeIgnored() {
        return cert.getIgnore() != null;
    }

    public boolean isPSS() {
        return Utils.isTrue(cert.getKeyAlgo().isPss());
    }

    public boolean isSelfSigned() {
        return getKey().equals(this.getIssuer());
    }

    public Date getNotBefore() {
        return convert(cert.getNotBefore());
    }

    public Date getNotAfter() {
        return convert(cert.getNotAfter());
    }

    public Date getRevocationDate() {
        return convert(cert.getRevocation());
    }

    public RevocationReason getRevocationReason() {
        if (cert.getRevocation() != null) {
            return cert.getRevocation().getReason();
        }
        return null;
    }

    public boolean isSuspended() {
        return cert.getSuspended() != null;
    }

    public XmlEntityKey getAIA() {
        return cert.getAia();
    }

    public XmlEntityKey getOCSP() {
        return cert.getOcsp();
    }

    public EntityId getOCSPResponder() {
        return convert(cert.getOcspResponder());
    }

    private EntityId convert(XmlEntityKey key) {
        if (key != null) {
            EntityId id = new EntityId();
            id.setSerialNumber(key.getSerialNumber());
            id.setIssuerName(key.getValue());
            return id;
        }
        return null;
    }

    public XmlCRLType getCRL() {
        return cert.getCrl();
    }

    public String getSubject() {
        return cert.getSubject();
    }

    public EntityId getIssuer() {
        return convert(cert.getIssuer());
    }

    public XmlKeyAlgo getKeyAlgo() {
        return cert.getKeyAlgo();
    }

    public XmlDigestAlgo getDigestAlgo() {
        return cert.getDigestAlgo();
    }

    public KeyUsage getKeyUsage() {
        XmlKeyUsages keyUsages = cert.getKeyUsages();
        if (keyUsages != null && keyUsages.getKeyUsage() != null) {
            int result = 0;
            List<String> kus = keyUsages.getKeyUsage();
            for (String ku : kus) {
                if ("crlSign".equals(ku)) {
                    result |= KeyUsage.cRLSign;
                } else if ("dataEncipherment".equals(ku)) {
                    result |= KeyUsage.dataEncipherment;
                } else if ("decipherOnly".equals(ku)) {
                    result |= KeyUsage.decipherOnly;
                } else if ("digitalSignature".equals(ku)) {
                    result |= KeyUsage.digitalSignature;
                } else if ("encipherOnly".equals(ku)) {
                    result |= KeyUsage.encipherOnly;
                } else if ("keyAgreement".equals(ku)) {
                    result |= KeyUsage.keyAgreement;
                } else if ("keyCertSign".equals(ku)) {
                    result |= KeyUsage.keyCertSign;
                } else if ("keyEncipherment".equals(ku)) {
                    result |= KeyUsage.keyEncipherment;
                } else if ("nonRepudiation".equals(ku)) {
                    result |= KeyUsage.nonRepudiation;
                } else {
                    throw new RuntimeException("Unsupported " + ku);
                }
            }
            return new KeyUsage(result);
        }
        return null;
    }

    private Date convert(XmlDateDefinitionType ddt) {
        if (ddt != null) {
            Calendar cal = Calendar.getInstance();
            if (ddt.getYear() != null) {
                cal.add(Calendar.YEAR, ddt.getYear());
            }
            if (ddt.getMonth() != null) {
                cal.add(Calendar.MONTH, ddt.getMonth());
            }
            if (ddt.getDay() != null) {
                cal.add(Calendar.DAY_OF_MONTH, ddt.getDay());
            }
            return cal.getTime();
        }
        return null;
    }

    public CertificatePolicies getCertificatePolicies() {
        if (cert.getCertificatePolicies() != null && !CollectionUtils.isEmpty(cert.getCertificatePolicies().getCertificatePolicy())) {
            PolicyInformation[] policyInformation = new PolicyInformation[cert.getCertificatePolicies().getCertificatePolicy().size()];
            int index = 0;
            for (String certificatePolicyEntry : cert.getCertificatePolicies().getCertificatePolicy()) {
                policyInformation[index] = new PolicyInformation(getPolicyOid(certificatePolicyEntry));
                index = index + 1;
            }
            return new CertificatePolicies(policyInformation);
        }
        return null;
    }

    public ASN1Sequence getQCStatementsIds() {
        if ((cert.getQcStatementIds() != null && !CollectionUtils.isEmpty(cert.getQcStatementIds().getQcStatement())) || (cert.getQcTypes() != null && !CollectionUtils.isEmpty(cert.getQcTypes().getQcType()))) {

            ASN1EncodableVector vector = new ASN1EncodableVector();

            // QC Statements IDs
            if (cert.getQcStatementIds() != null && !CollectionUtils.isEmpty(cert.getQcStatementIds().getQcStatement())) {
                for (String qcStatement : cert.getQcStatementIds().getQcStatement()) {
                    vector.add(new DERSequence(getOid(qcStatement)));
                }
            }

            // QC Types
            if (cert.getQcTypes() != null && !CollectionUtils.isEmpty(cert.getQcTypes().getQcType())) {
                ASN1EncodableVector typeVector = new ASN1EncodableVector();
                for (String qcTypes : cert.getQcTypes().getQcType()) {
                    typeVector.add(getOid(qcTypes));
                }

                QCStatement qcTypes = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, new DERSequence(typeVector));

                vector.add(qcTypes);
            }

            // QC CClegislation
            if (cert.getQcCClegislation() != null && !CollectionUtils.isEmpty(cert.getQcCClegislation().getCountryName())) {
                ASN1EncodableVector cclegislationVector = new ASN1EncodableVector();
                for (String qcCClegislation : cert.getQcCClegislation().getCountryName()) {
                    cclegislationVector.add(new DERPrintableString(qcCClegislation));
                }

                QCStatement qcCClegislation = new QCStatement(new ASN1ObjectIdentifier(QCStatementOids.QC_CCLEGISLATION.getOid()), new DERSequence(cclegislationVector));

                vector.add(qcCClegislation);
            }

            return new DERSequence(vector);
        }
        return null;
    }

    /**
     * Get CertificatePolicies OID from enum or return entry params if no match found
     *
     * @param policy {@link String}
     * @return {@link ASN1ObjectIdentifier}
     */
    private ASN1ObjectIdentifier getPolicyOid(String policy) {
        try {
            CertificatePolicyOids oid = CertificatePolicyOids.valueOf(policy.toUpperCase());
            return new ASN1ObjectIdentifier(oid.getOid());
        } catch (IllegalArgumentException e) {
            return new ASN1ObjectIdentifier(policy);
        }
    }

    /**
     * Get QCStatements OID from enum or return entry params if no match found
     *
     * @param qcString {@link String}
     * @return {@link ASN1ObjectIdentifier}
     */
    private ASN1ObjectIdentifier getOid(String qcString) {
        try {
            QCStatementOids oid = QCStatementOids.valueOf(qcString.toUpperCase());
            return new ASN1ObjectIdentifier(oid.getOid());
        } catch (IllegalArgumentException e) {
            return new ASN1ObjectIdentifier(qcString);
        }
    }

}
