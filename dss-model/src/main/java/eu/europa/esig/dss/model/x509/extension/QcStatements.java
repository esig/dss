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

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;

import java.util.ArrayList;
import java.util.List;

/**
 * This class contains the QcStatement information based on ETSI EN 319 412-1/5 and ETSI TS 119 495
 */
public class QcStatements extends CertificateExtension {

    /**
     * esi4-qcStatement-1 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-qcs-QcCompliance }
     * id-etsi-qcs-QcCompliance OBJECT IDENTIFIER ::= { id-etsi-qcs 1 }
     */
    private boolean qcCompliance;

    /**
     * esi4-qcStatement-2 QC-STATEMENT ::= { SYNTAX QcEuLimitValue IDENTIFIED BY id-etsi-qcs-QcLimitValue }
     * id-etsi-qcs-QcLimitValue OBJECT IDENTIFIER ::= { id-etsi-qcs 2 }
     */
    private QCLimitValue qcLimitValue;

    /**
     * esi4-qcStatement-3 QC-STATEMENT ::= { SYNTAX QcEuRetentionPeriod IDENTIFIED BY id-etsi-qcs-QcRetentionPeriod }
     * id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::= { id-etsi-qcs 3 }
     */
    private Integer qcEuRetentionPeriod;

    /**
     * esi4-qcStatement-4 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-qcs-QcSSCD }
     * id-etsi-qcs-QcSSCD OBJECT IDENTIFIER ::= { id-etsi-qcs 4 }
     */
    private boolean qcQSCD;

    /**
     * esi4-qcStatement-5 QC-STATEMENT ::= { SYNTAX QcEuPDS IDENTIFIED BY id-etsi-qcs-QcPDS }
     * id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::= { id-etsi-qcs 5 }
     */
    private List<PdsLocation> qcEuPDS;

    /**
     * esi4-qcStatement-6 QC-STATEMENT ::= { SYNTAX QcType IDENTIFIED BY id-etsi-qcs-QcType }
     * id-etsi-qcs-QcType OBJECT IDENTIFIER ::= { id-etsi-qcs 6 }
     */
    private List<QCType> qcTypes;

    /**
     * esi4-qcStatement-7 QC-STATEMENT ::= { SYNTAX QcCClegislation IDENTIFIED BY id-etsi-qcsQcCClegislation }
     * id-etsi-qcs-QcCClegislation OBJECT IDENTIFIER ::= { id-etsi-qcs 7 }
     *
     * QcCClegislation ::= SEQUENCE OF CountryName
     * CountryName ::= PrintableString (SIZE (2)) (CONSTRAINED BY { -- ISO 3166-1 [6] alpha-2 codes only -- })
     */
    private List<String> qcLegislationCountryCodes;

    /**
     * id-etsi-qcs-semantics-identifiers OBJECT IDENTIFIER ::= { itu-t(0)
     * identified-organization(4) etsi(0) id-cert-profile(194121) 1 }
     */
    private SemanticsIdentifier qcSemanticsIdentifier;

    /**
     * etsi-psd2-qcStatement QC-STATEMENT ::= {SYNTAX PSD2QcType IDENTIFIED BY id-etsi-psd2-qcStatement }
     * id-etsi-psd2-qcStatement OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) psd2(19495) qcstatement(2) }
     */
    private PSD2QcType psd2QcType;

    /**
     * This list contains OIDs defined in QcStatements, which are not supported by the current implementation
     */
    private List<String> otherOids = new ArrayList<>();

    /**
     * Default constructor instantiating object with null values
     */
    public QcStatements() {
        super(CertificateExtensionEnum.QC_STATEMENTS.getOid());
    }

    /**
     * Gets if the certificate is qc-compliant
     *
     * @return TRUE if qc-compliance extension is present, FALSE otherwise
     */
    public boolean isQcCompliance() {
        return qcCompliance;
    }

    /**
     * Sets if the qc-compliance extension is present
     *
     * @param qcCompliance if qc-compliance extension is present
     */
    public void setQcCompliance(boolean qcCompliance) {
        this.qcCompliance = qcCompliance;
    }

    /**
     * Gets the qc-limit-value
     *
     * @return {@link QCLimitValue}
     */
    public QCLimitValue getQcLimitValue() {
        return qcLimitValue;
    }

    /**
     * Sets the qc-limit-value
     *
     * @param qcLimitValue {@link QCLimitValue}
     */
    public void setQcLimitValue(QCLimitValue qcLimitValue) {
        this.qcLimitValue = qcLimitValue;
    }

    /**
     * Gets the qc-eu-retention-period
     *
     * @return {@link Integer}
     */
    public Integer getQcEuRetentionPeriod() {
        return qcEuRetentionPeriod;
    }

    /**
     * Sets the qc-eu-retention-period
     *
     * @param qcEuRetentionPeriod {@link Integer}
     */
    public void setQcEuRetentionPeriod(Integer qcEuRetentionPeriod) {
        this.qcEuRetentionPeriod = qcEuRetentionPeriod;
    }

    /**
     * Gets if the certificate is qc-qscd
     *
     * @return TRUE if the qc-qscd extension is present, FALSE otherwise
     */
    public boolean isQcQSCD() {
        return qcQSCD;
    }

    /**
     * Sets if the certificate is qc-qscd
     *
     * @param qcQSCD if the qc-qscd extension is present
     */
    public void setQcQSCD(boolean qcQSCD) {
        this.qcQSCD = qcQSCD;
    }

    /**
     * Gets the qc-eu-pds
     *
     * @return a list of {@link PdsLocation}s
     */
    public List<PdsLocation> getQcEuPDS() {
        return qcEuPDS;
    }

    /**
     * Sets the qc-eu-pds
     *
     * @param qcEuPDS a list of {@link PdsLocation}s
     */
    public void setQcEuPDS(List<PdsLocation> qcEuPDS) {
        this.qcEuPDS = qcEuPDS;
    }

    /**
     * Gets a list of {@code QCType}s
     *
     * @return a list of {@link QCType}s
     */
    public List<QCType> getQcTypes() {
        return qcTypes;
    }

    /**
     * Sets a list of {@code QCType}s
     *
     * @param qcTypes a list of {@link QCType}s
     */
    public void setQcTypes(List<QCType> qcTypes) {
        this.qcTypes = qcTypes;
    }

    /**
     * Gets qc-legislation-country-codes
     *
     * @return a list of {@link String} country codes
     */
    public List<String> getQcLegislationCountryCodes() {
        return qcLegislationCountryCodes;
    }

    /**
     * Sets qc-legislation-country-codes
     *
     * @param qcLegislationCountryCodes a list of {@link String} country codes
     */
    public void setQcLegislationCountryCodes(List<String> qcLegislationCountryCodes) {
        this.qcLegislationCountryCodes = qcLegislationCountryCodes;
    }

    /**
     * Gets the qc-semantics-identifier
     *
     * @return {@link SemanticsIdentifier}
     */
    public SemanticsIdentifier getQcSemanticsIdentifier() {
        return qcSemanticsIdentifier;
    }

    /**
     * Sets the qc-semantics-identifier
     *
     * @param qcSemanticsIdentifier {@link SemanticsIdentifier}
     */
    public void setQcSemanticsIdentifier(SemanticsIdentifier qcSemanticsIdentifier) {
        this.qcSemanticsIdentifier = qcSemanticsIdentifier;
    }

    /**
     * Gets the psd2-qc-type
     *
     * @return {@link PSD2QcType}
     */
    public PSD2QcType getPsd2QcType() {
        return psd2QcType;
    }

    /**
     * Sets the psd2-qc-type
     *
     * @param psd2QcType {@link PSD2QcType}
     */
    public void setPsd2QcType(PSD2QcType psd2QcType) {
        this.psd2QcType = psd2QcType;
    }

    /**
     * This method returns a list of found OIDs not supported by the current implementation
     *
     * @return a list of {@link String}
     */
    public List<String> getOtherOids() {
        return otherOids;
    }

    /**
     * Adds a found OID not supported by the implementation
     *
     * @param oid {@link String}
     */
    public void addOtherOid(String oid) {
        this.otherOids.add(oid);
    }

}
