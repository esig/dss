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
package eu.europa.esig.dss.model.x509;

import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;

import java.util.List;

/**
 * This class contains the QcStatement information based on ETSI EN 319 412-1/5 and ETSI TS 119 495
 */
public class QcStatements {

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

    public boolean isQcCompliance() {
        return qcCompliance;
    }

    public void setQcCompliance(boolean qcCompliance) {
        this.qcCompliance = qcCompliance;
    }

    public QCLimitValue getQcLimitValue() {
        return qcLimitValue;
    }

    public void setQcLimitValue(QCLimitValue qcLimitValue) {
        this.qcLimitValue = qcLimitValue;
    }

    public Integer getQcEuRetentionPeriod() {
        return qcEuRetentionPeriod;
    }

    public void setQcEuRetentionPeriod(Integer qcEuRetentionPeriod) {
        this.qcEuRetentionPeriod = qcEuRetentionPeriod;
    }

    public boolean isQcQSCD() {
        return qcQSCD;
    }

    public void setQcQSCD(boolean qcQSCD) {
        this.qcQSCD = qcQSCD;
    }

    public List<PdsLocation> getQcEuPDS() {
        return qcEuPDS;
    }

    public void setQcEuPDS(List<PdsLocation> qcEuPDS) {
        this.qcEuPDS = qcEuPDS;
    }

    public List<QCType> getQcTypes() {
        return qcTypes;
    }

    public void setQcTypes(List<QCType> qcTypes) {
        this.qcTypes = qcTypes;
    }

    public List<String> getQcLegislationCountryCodes() {
        return qcLegislationCountryCodes;
    }

    public void setQcLegislationCountryCodes(List<String> qcLegislationCountryCodes) {
        this.qcLegislationCountryCodes = qcLegislationCountryCodes;
    }

    public SemanticsIdentifier getQcSemanticsIdentifier() {
        return qcSemanticsIdentifier;
    }

    public void setQcSemanticsIdentifier(SemanticsIdentifier qcSemanticsIdentifier) {
        this.qcSemanticsIdentifier = qcSemanticsIdentifier;
    }

    public PSD2QcType getPsd2QcType() {
        return psd2QcType;
    }

    public void setPsd2QcType(PSD2QcType psd2QcType) {
        this.psd2QcType = psd2QcType;
    }

}
