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

/**
 * An utils class to retrieve qc-statement from a certificate token
 *
 */
public class QcStatementUtils {

    private static final Logger LOG = LoggerFactory.getLogger(QcStatementUtils.class);

    /**
     * Singleton
     */
    private QcStatementUtils() {
    }

    /**
     * Extracts the QCStatements from a certificate token
     *
     * @param certToken {@link CertificateToken}
     * @return {@link QcStatements}
     */
    public static QcStatements getQcStatements(CertificateToken certToken) {
        final byte[] qcStatements = certToken.getCertificate().getExtensionValue(Extension.qCStatements.getId());
        if (Utils.isArrayNotEmpty(qcStatements)) {
            try {
                final ASN1Sequence qcStatementsSeq = DSSASN1Utils.getAsn1SequenceFromDerOctetString(qcStatements);
                return getQcStatements(qcStatementsSeq);

            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.warn("Unable to extract QcStatements : {}. Obtained binaries : '{}'",
                            e.getMessage(), Utils.toBase64(qcStatements));
                } else {
                    LOG.warn("Unable to extract QcStatements : {}", e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * Extracts the QCStatements from a qcStatementsSeq
     *
     * @param qcStatementsSeq {@link ASN1Sequence}
     * @return {@link QcStatements}
     */
    public static QcStatements getQcStatements(ASN1Sequence qcStatementsSeq) {
        if (qcStatementsSeq == null) {
            return null;
        }

        final QcStatements result = new QcStatements();
        for (int i = 0; i < qcStatementsSeq.size(); i++) {
            final QCStatement statement = getQCStatement(qcStatementsSeq.getObjectAt(i));
            if (statement != null) {
                final ASN1ObjectIdentifier objectIdentifier = statement.getStatementId();
                String oid = objectIdentifier.getId();
                final ASN1Encodable statementInfo = statement.getStatementInfo();
                if (isQcCompliance(oid)) {
                    result.setQcCompliance(true);
                } else if (isQcLimitValue(oid)) {
                    result.setQcLimitValue(getQcLimitValue(statementInfo));
                } else if (isQcRetentionPeriod(oid)) {
                    result.setQcEuRetentionPeriod(getQcEuRetentionPeriod(statementInfo));
                } else if (isQcSSCD(oid)) {
                    result.setQcQSCD(true);
                } else if (isQcPds(oid)) {
                    result.setQcEuPDS(getQcEuPDS(statementInfo));
                } else if (isQcType(oid)) {
                    result.setQcTypes(getQcTypes(statementInfo));
                } else if (isQcCClegislation(oid)) {
                    result.setQcLegislationCountryCodes(getQcLegislationCountryCodes(statementInfo));
                } else if (isQcSemanticsIdentifier(oid)) {
                    result.setQcSemanticsIdentifier(getQcSemanticsIdentifier(statementInfo));
                } else if (isPsd2QcType(oid)) {
                    result.setPsd2QcType(getPsd2QcType(statementInfo));
                } else {
                    LOG.warn("Not supported QcStatement with OID : '{}'", oid);
                    result.addOtherOid(oid);
                }
            }
        }
        return result;
    }

    /**
     * This method verifies of the given OID is a QcCompliance statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcCompliance, FALSE otherwise
     */
    public static boolean isQcCompliance(String oid) {
        return ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a QcLimitValue statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcLimitValue, FALSE otherwise
     */
    public static boolean isQcLimitValue(String oid) {
        return ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a QcRetentionPeriod statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcRetentionPeriod, FALSE otherwise
     */
    public static boolean isQcRetentionPeriod(String oid) {
        return ETSIQCObjectIdentifiers.id_etsi_qcs_RetentionPeriod.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a QcSSCD statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcSSCD, FALSE otherwise
     */
    public static boolean isQcSSCD(String oid) {
        return ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a QcPds statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcPds, FALSE otherwise
     */
    public static boolean isQcPds(String oid) {
        return ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a QcType statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcType, FALSE otherwise
     */
    public static boolean isQcType(String oid) {
        return ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a QcCClegislation statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcCClegislation, FALSE otherwise
     */
    public static boolean isQcCClegislation(String oid) {
        return OID.id_etsi_qcs_QcCClegislation.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a QcSemanticsIdentifier statement
     *
     * @param oid {@link String} to check
     * @return TRUE if QcSemanticsIdentifier, FALSE otherwise
     */
    public static boolean isQcSemanticsIdentifier(String oid) {
        return RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.getId().equals(oid);
    }

    /**
     * This method verifies of the given OID is a Psd2QcType statement
     *
     * @param oid {@link String} to check
     * @return TRUE if Psd2QcType, FALSE otherwise
     */
    public static boolean isPsd2QcType(String oid) {
        return OID.psd2_qcStatement.getId().equals(oid);
    }

    private static QCStatement getQCStatement(ASN1Encodable qcStatement) {
        if (qcStatement != null) {
            try {
                return QCStatement.getInstance(qcStatement);
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.warn("Unable to extract QCStatement : {}. Obtained sequence binaries : '{}'",
                            e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(qcStatement)));
                } else {
                    LOG.warn("Unable to extract QCStatement : {}", e.getMessage());
                }
            }
        }
        return null;
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
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to extract QcLimitValue : {}. Obtained binaries : '{}'",
                        e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(statementInfo)));
            } else {
                LOG.warn("Unable to extract QcLimitValue : {}", e.getMessage());
            }
            return null;
        }
    }

    private static Integer getQcEuRetentionPeriod(ASN1Encodable statementInfo) {
        try {
            ASN1Integer integer = ASN1Integer.getInstance(statementInfo);
            return integer.intValueExact();

        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to extract QcEuRetentionPeriod : {}. Obtained binaries : '{}'",
                        e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(statementInfo)));
            } else {
                LOG.warn("Unable to extract QcEuRetentionPeriod : {}", e.getMessage());
            }
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
                    result.add(getPdsLocation(seq));
                } else {
                    LOG.warn("ASN1Sequence in QcEuPDS does not contain ASN1Sequence, but {}",
                            e1.getClass().getName());
                }
            }

        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to extract QcEuPDS : {}. Obtained binaries : '{}'",
                        e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(statementInfo)));
            } else {
                LOG.warn("Unable to extract QcEuPDS : {}", e.getMessage());
            }
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
        final List<String> oids = new ArrayList<>();
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(statementInfo);
            for (int i = 0; i < sequence.size(); i++) {
                final ASN1Encodable e1 = sequence.getObjectAt(i);
                if (e1 instanceof ASN1ObjectIdentifier) {
                    final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e1;
                    oids.add(oid.getId());

                } else {
                    LOG.warn("ASN1Sequence in QcTypes does not contain ASN1ObjectIdentifier, but {}",
                            e1.getClass().getName());
                }
            }

        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to extract QcTypes : {}. Obtained binaries : '{}'",
                        e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(statementInfo)));
            } else {
                LOG.warn("Unable to extract QcTypes : {}", e.getMessage());
            }
        }

        return getQcTypes(oids);
    }

    /**
     * This method returns a list of {@code QCType}s from a list of given QcType OIDs
     *
     * @param oids a list of {@link String}s representing QcType OIDs
     * @return a list of {@link QCType}s
     */
    public static List<QCType> getQcTypes(List<String> oids) {
        List<QCType> result = new ArrayList<>();
        for (String oid : oids) {
            if (Utils.isStringNotBlank(oid)) {
                QCType type = QCType.fromOid(oid);
                result.add(type);
            } else {
                LOG.warn("Empty QcType OID is skipped.");
            }
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
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to extract QcCClegislation : {}. Obtained binaries : '{}'",
                        e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(statementInfo)));
            } else {
                LOG.warn("Unable to extract QcCClegislation : {}", e.getMessage());
            }
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
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to extract QcSemanticsIdentifiers : {}. Obtained binaries : '{}'",
                        e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(statementInfo)));
            } else {
                LOG.warn("Unable to extract QcSemanticsIdentifiers : {}", e.getMessage());
            }
        }
        return null;
    }

    private static PSD2QcType getPsd2QcType(ASN1Encodable statementInfo) {
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
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to extract PSD2-QcStatement : {}. Obtained binaries : '{}'",
                        e.getMessage(), Utils.toBase64(DSSASN1Utils.getDEREncoded(statementInfo)));
            } else {
                LOG.warn("Unable to extract PSD2-QcStatement : {}", e.getMessage());
            }
            return null;
        }
    }

    /**
     * This method verifies whether the given {@code qcStatementOid} is present within the {@code QcStatements}
     *
     * @param qcStatements {@link QcStatements} to be verified
     * @param qcStatementOid {@link String} representing OID of a QCStatement to be checked
     * @return TRUE if a QCStatement with the given OID is present, FALSE otherwise
     */
    public static boolean isQcStatementPresent(QcStatements qcStatements, String qcStatementOid) {
        if (isQcCompliance(qcStatementOid)) {
            return qcStatements.isQcCompliance();
        } else if (isQcLimitValue(qcStatementOid)) {
            return qcStatements.getQcLimitValue() != null;
        } else if (isQcRetentionPeriod(qcStatementOid)) {
            return qcStatements.getQcEuRetentionPeriod() != null;
        } else if (isQcSSCD(qcStatementOid)) {
            return qcStatements.isQcQSCD();
        } else if (isQcPds(qcStatementOid)) {
            return Utils.isCollectionNotEmpty(qcStatements.getQcEuPDS());
        } else if (isQcType(qcStatementOid)) {
            return Utils.isCollectionNotEmpty(qcStatements.getQcTypes());
        } else if (isQcCClegislation(qcStatementOid)) {
            return Utils.isCollectionNotEmpty(qcStatements.getQcLegislationCountryCodes());
        } else if (isQcSemanticsIdentifier(qcStatementOid)) {
            return qcStatements.getQcSemanticsIdentifier() != null;
        } else if (isPsd2QcType(qcStatementOid)) {
            return qcStatements.getPsd2QcType() != null;
        } else {
            return qcStatements.getOtherOids().contains(qcStatementOid);
        }
    }

    /**
     * This method verifies whether a QCType with a given {@code qcTypeOid} is present
     * within provided {@code QcStatements}
     *
     * @param qcStatements {@link QcStatements} to check QCTypes from
     * @param qcTypeOid {@link String} representing a QCType OID to be verified
     * @return TRUE of the QCType with a given OID is present, FALSE otherwise
     */
    public static boolean isQcTypePresent(QcStatements qcStatements, String qcTypeOid) {
        List<QCType> qcTypes = qcStatements.getQcTypes();
        if (Utils.isCollectionNotEmpty(qcTypes)) {
            for (QCType qcType : qcTypes) {
                if (qcTypeOid.equals(qcType.getOid())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * This method verifies whether a QCLegislation code is present within provided {@code QcStatements}
     *
     * @param qcStatements {@link QcStatements} to check QCLegislation from
     * @param qcLegislation {@link String} representing a QCLegislation country code to be verified
     * @return TRUE of the QCLegislation is present, FALSE otherwise
     */
    public static boolean isQcLegislationPresent(QcStatements qcStatements, String qcLegislation) {
        List<String> qcLegislationCountryCodes = qcStatements.getQcLegislationCountryCodes();
        if (Utils.isCollectionNotEmpty(qcLegislationCountryCodes)) {
            return qcLegislationCountryCodes.contains(qcLegislation);
        }
        return false;
    }

}
