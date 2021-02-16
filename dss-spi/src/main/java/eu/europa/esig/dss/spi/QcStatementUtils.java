package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.RoleOfPspOid;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.PSD2QcType;
import eu.europa.esig.dss.model.x509.PdsLocation;
import eu.europa.esig.dss.model.x509.QCLimitValue;
import eu.europa.esig.dss.model.x509.QcStatements;
import eu.europa.esig.dss.model.x509.RoleOfPSP;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class QcStatementUtils {

    private static final Logger LOG = LoggerFactory.getLogger(QcStatementUtils.class);

    private QcStatementUtils() {
    }

    public static QcStatements getQcStatements(CertificateToken certToken) {
        final byte[] qcStatements = certToken.getCertificate().getExtensionValue(Extension.qCStatements.getId());
        if (Utils.isArrayNotEmpty(qcStatements)) {
            final ASN1Sequence qcStatementsSeq = DSSASN1Utils.getAsn1SequenceFromDerOctetString(qcStatements);
            return getQcStatements(qcStatementsSeq);
        }
        return null;
    }

    public static QcStatements getQcStatements(ASN1Sequence qcStatementsSeq) {
        if (qcStatementsSeq == null) {
            return null;
        }

        QcStatements result = new QcStatements();
        for (int i = 0; i < qcStatementsSeq.size(); i++) {
            final QCStatement statement = QCStatement.getInstance(qcStatementsSeq.getObjectAt(i));
            final ASN1ObjectIdentifier objectIdentifier = statement.getStatementId();
            final ASN1Encodable statementInfo = statement.getStatementInfo();
            if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.equals(objectIdentifier)) {
                result.setQcCompliance(true);
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.equals(objectIdentifier)) {
                result.setQcLimitValue(getQcLimitValue(statementInfo));
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_RetentionPeriod.equals(objectIdentifier)) {
                result.setQcEuRetentionPeriod(getQcEuRetentionPeriod(statementInfo));
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.equals(objectIdentifier)) {
                result.setQcQSCD(true);
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.equals(objectIdentifier)) {
                result.setQcEuPDS(getQcEuPDS(statementInfo));
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.equals(objectIdentifier)) {
                result.setQcTypes(getQcTypes(statementInfo));
            } else if (OID.id_etsi_qcs_QcCClegislation.equals(objectIdentifier)) {
                result.setQcLegislationCountryCodes(getQcLegislationCountryCodes(statementInfo));
            } else if (RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.equals(objectIdentifier)) {
                result.setQcSemanticsIdentifier(getQcSemanticsIdentifier(statementInfo));
            } else if (OID.psd2_qcStatement.equals(objectIdentifier)) {
                result.setPsd2QcType(getPsdc2QcType(statementInfo));
            } else {
                LOG.warn("Not supported QcStatement with oid {}", objectIdentifier.getId());
            }
        }
        return result;
    }

    private static QCLimitValue getQcLimitValue(ASN1Encodable statementInfo) {
        try {
            MonetaryValue monetaryValue = MonetaryValue.getInstance(statementInfo);
            QCLimitValue result = new QCLimitValue();
            result.setCurrency(monetaryValue.getCurrency().getAlphabetic());
            result.setAmount(monetaryValue.getAmount().intValue());
            result.setExponent(monetaryValue.getExponent().intValue());
            return result;
        } catch (Exception e) {
            LOG.warn("Unable to extract QcLimitValue : {}", e.getMessage());
            return null;
        }
    }

    private static Integer getQcEuRetentionPeriod(ASN1Encodable statementInfo) {
        try {
            ASN1Integer integer = ASN1Integer.getInstance(statementInfo);
            return integer.intValueExact();
        } catch (Exception e) {
            LOG.warn("Unable to extract QcEuRetentionPeriod : {}", e.getMessage());
            return null;
        }
    }

    private static List<PdsLocation> getQcEuPDS(ASN1Encodable statementInfo) {
        List<PdsLocation> result = new ArrayList<>();
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(statementInfo);
            for (int i = 0; i < sequence.size(); i++) {
                final ASN1Encodable e1 = sequence.getObjectAt(i);
                if (e1 instanceof ASN1Sequence) {
                    ASN1Sequence seq = (ASN1Sequence) e1;
                    PdsLocation pds = getPdsLocation(seq);
                    if (pds != null) {
                        result.add(pds);
                    }
                } else {
                    LOG.warn("ASN1Sequence in QcEuPDS does not contain ASN1Sequence, but {}",
                            e1.getClass().getName());
                }
            }
        } catch (Exception e) {
            LOG.warn("Unable to extract QcEuPDS : {}", e.getMessage());
        }
        return result;
    }

    private static PdsLocation getPdsLocation(ASN1Sequence seq) {
        PdsLocation pdsLocation = new PdsLocation();
        pdsLocation.setUrl(DSSASN1Utils.getString(seq.getObjectAt(0)));
        pdsLocation.setLanguage(DSSASN1Utils.getString(seq.getObjectAt(1)));
        return pdsLocation;
    }

    private static List<QCType> getQcTypes(ASN1Encodable statementInfo) {
        List<QCType> result = new ArrayList<>();
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(statementInfo);
            for (int i = 0; i < sequence.size(); i++) {
                final ASN1Encodable e1 = sequence.getObjectAt(i);
                if (e1 instanceof ASN1ObjectIdentifier) {
                    final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e1;
                    QCType type = QCType.fromOid(oid.getId());
                    if (type != null) {
                        result.add(type);
                    } else {
                        LOG.warn("Not supported QcType : {}", oid.getId());
                    }
                } else {
                    LOG.warn("ASN1Sequence in QcTypes does not contain ASN1ObjectIdentifer, but {}",
                            e1.getClass().getName());
                }
            }
        } catch (Exception e) {
            LOG.warn("Unable to extract QcTypes : {}", e.getMessage());
        }
        return result;
    }

    private static List<String> getQcLegislationCountryCodes(ASN1Encodable statementInfo) {
        List<String> result = new ArrayList<>();
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(statementInfo);
            for (int i = 0; i < sequence.size(); i++) {
                String countryCode = DSSASN1Utils.getString(sequence.getObjectAt(i));
                if (countryCode != null) {
                    result.add(countryCode);
                }
            }
        } catch (Exception e) {
            LOG.warn("Unable to extract QcCClegislation : {}", e.getMessage());
        }
        return result;
    }

    private static SemanticsIdentifier getQcSemanticsIdentifier(ASN1Encodable statementInfo) {
        try {
            SemanticsInformation semanticsInfo = SemanticsInformation.getInstance(statementInfo);
            if (semanticsInfo != null && semanticsInfo.getSemanticsIdentifier() != null) {
                return SemanticsIdentifier.fromOid(semanticsInfo.getSemanticsIdentifier().getId());
            }
        } catch (Exception e) {
            LOG.warn("Unable to extract QcSemanticsIdentifiers : {}", e.getMessage());
        }
        return null;
    }

    private static PSD2QcType getPsdc2QcType(ASN1Encodable statementInfo) {
        try {
            PSD2QcType result = new PSD2QcType();

            ASN1Sequence sequence = ASN1Sequence.getInstance(statementInfo);
            ASN1Sequence rolesSeq = ASN1Sequence.getInstance(sequence.getObjectAt(0));

            List<RoleOfPSP> rolesOfPSP = new ArrayList<>();
            for (int i = 0; i < rolesSeq.size(); i++) {
                ASN1Sequence oneRoleSeq = ASN1Sequence.getInstance(rolesSeq.getObjectAt(i));
                RoleOfPSP roleOfPSP = new RoleOfPSP();
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) oneRoleSeq.getObjectAt(0);
                roleOfPSP.setPspOid(RoleOfPspOid.fromOid(oid.getId()));
                roleOfPSP.setPspName(DSSASN1Utils.getString(oneRoleSeq.getObjectAt(1)));
                rolesOfPSP.add(roleOfPSP);
            }
            result.setRolesOfPSP(rolesOfPSP);
            result.setNcaName(DSSASN1Utils.getString(sequence.getObjectAt(1)));
            result.setNcaId(DSSASN1Utils.getString(sequence.getObjectAt(2)));
            return  result;
        } catch (Exception e) {
            LOG.warn("Unable to extract PSD2-QcStatement : {}", e.getMessage());
            return null;
        }
    }

}
