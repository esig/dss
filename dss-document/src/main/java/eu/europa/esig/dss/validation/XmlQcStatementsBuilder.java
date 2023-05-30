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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2QcInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcSSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRoleOfPSP;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.RoleOfPspOid;
import eu.europa.esig.dss.model.x509.extension.PSD2QcType;
import eu.europa.esig.dss.model.x509.extension.PdsLocation;
import eu.europa.esig.dss.model.x509.extension.QCLimitValue;
import eu.europa.esig.dss.model.x509.extension.QcStatements;
import eu.europa.esig.dss.model.x509.extension.RoleOfPSP;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to build a {@code XmlQcStatements} object and enveloped objects
 *
 */
public class XmlQcStatementsBuilder {

    /**
     * Default constructor
     */
    public XmlQcStatementsBuilder() {
        // empty
    }

    /**
     * Builds the {@code XmlQcStatements}
     *
     * @param qcStatements {@link QcStatements}
     * @return {@link XmlQcStatements}
     */
    public XmlQcStatements build(QcStatements qcStatements) {
        XmlQcStatements result = new XmlQcStatements();
        result.setOID(qcStatements.getOid());
        result.setCritical(qcStatements.isCritical());
        result.setQcCompliance(buildXmlQcCompliance(qcStatements.isQcCompliance()));
        result.setQcSSCD(buildXmlQcSSCD(qcStatements.isQcQSCD()));
        if (qcStatements.getQcEuRetentionPeriod() != null) {
            result.setQcEuRetentionPeriod(qcStatements.getQcEuRetentionPeriod());
        }
        if (qcStatements.getQcLimitValue() != null) {
            result.setQcEuLimitValue(buildQcEuLimitValue(qcStatements.getQcLimitValue()));
        }
        if (Utils.isCollectionNotEmpty(qcStatements.getQcTypes())) {
            result.setQcTypes(buildXmlQcTypes(qcStatements.getQcTypes()));
        }
        if (Utils.isCollectionNotEmpty(qcStatements.getQcEuPDS())) {
            result.setQcEuPDS(buildXmlQcEuPSD(qcStatements.getQcEuPDS()));
        }
        if (qcStatements.getQcSemanticsIdentifier() != null) {
            result.setSemanticsIdentifier(buildSemanticsIdentifier(qcStatements.getQcSemanticsIdentifier()));
        }
        if (Utils.isCollectionNotEmpty(qcStatements.getQcLegislationCountryCodes())) {
            result.setQcCClegislation(qcStatements.getQcLegislationCountryCodes());
        }
        if (qcStatements.getPsd2QcType() != null) {
            result.setPSD2QcInfo(buildPSD2QcInfo(qcStatements.getPsd2QcType()));
        }
        if (Utils.isCollectionNotEmpty(qcStatements.getOtherOids())) {
            result.setOtherOIDs(buildXmlOIDs(qcStatements.getOtherOids()));
        }
        return result;
    }

    /**
     * Builds a list of XML QcEuPSDs
     *
     * @param qcEuPDS a list of {@code PdsLocation}s
     * @return a list of {@link XmlLangAndValue}s
     */
    public List<XmlLangAndValue> buildXmlQcEuPSD(List<PdsLocation> qcEuPDS) {
        List<XmlLangAndValue> result = new ArrayList<>();
        for (PdsLocation pdsLocation : qcEuPDS) {
            XmlLangAndValue xmlPdsLocation = new XmlLangAndValue();
            xmlPdsLocation.setLang(pdsLocation.getLanguage());
            xmlPdsLocation.setValue(pdsLocation.getUrl());
            result.add(xmlPdsLocation);
        }
        return result;
    }

    /**
     * Builds a {@code XmlQcSSCD}
     *
     * @param present TRUE if QSCD/SSCD is present, FALSE otherwise
     * @return {@link XmlQcSSCD}
     */
    public XmlQcSSCD buildXmlQcSSCD(boolean present) {
        XmlQcSSCD xmlQcSSCD = new XmlQcSSCD();
        xmlQcSSCD.setPresent(present);
        return xmlQcSSCD;
    }

    /**
     * Builds {@code XmlQcCompliance}
     *
     * @param present TRUE if QcCompliance is present, FALSE otherwise
     * @return {@link XmlQcCompliance}
     */
    public XmlQcCompliance buildXmlQcCompliance(boolean present) {
        XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
        xmlQcCompliance.setPresent(present);
        return xmlQcCompliance;
    }

    /**
     * Builds {@code XmlPSD2QcInfo}
     *
     * @param psd2QcStatement {@link PSD2QcType}
     * @return {@link XmlPSD2QcInfo}
     */
    public XmlPSD2QcInfo buildPSD2QcInfo(PSD2QcType psd2QcStatement) {
        XmlPSD2QcInfo xmlInfo = new XmlPSD2QcInfo();
        xmlInfo.setNcaId(psd2QcStatement.getNcaId());
        xmlInfo.setNcaName(psd2QcStatement.getNcaName());
        List<RoleOfPSP> rolesOfPSP = psd2QcStatement.getRolesOfPSP();
        List<XmlRoleOfPSP> psd2Roles = new ArrayList<>();
        for (RoleOfPSP roleOfPSP : rolesOfPSP) {
            XmlRoleOfPSP xmlRole = new XmlRoleOfPSP();
            RoleOfPspOid role = roleOfPSP.getPspOid();
            xmlRole.setOid(getXmlOid(role));
            xmlRole.setName(roleOfPSP.getPspName());
            psd2Roles.add(xmlRole);
        }
        xmlInfo.setRolesOfPSP(psd2Roles);
        return xmlInfo;
    }

    /**
     * Builds Semantics Identifier {@code XmlOID}
     *
     * @param semanticsIdentifier {@link OidDescription}
     * @return {@link XmlOID}
     */
    public XmlOID buildSemanticsIdentifier(OidDescription semanticsIdentifier) {
        return getXmlOid(semanticsIdentifier);
    }

    private XmlOID getXmlOid(OidDescription oidDescription) {
        if (oidDescription == null) {
            return null;
        }
        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue(oidDescription.getOid());
        xmlOID.setDescription(oidDescription.getDescription());
        return xmlOID;
    }

    /**
     * Builds a list of XML QcTypes
     *
     * @param qcTypes a list of {@link QCType}s
     * @return a list of {@link XmlOID}s
     */
    public List<XmlOID> buildXmlQcTypes(List<QCType> qcTypes) {
        List<XmlOID> result = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(qcTypes)) {
            for (QCType qcType : qcTypes) {
                XmlOID xmlOID = new XmlOID();
                xmlOID.setValue(qcType.getOid());
                xmlOID.setDescription(qcType.getDescription());
                result.add(xmlOID);
            }
        }
        return result;
    }

    /**
     * Builds a list of {@code XmlOID}s from a list of {@link String}s
     *
     * @param oids a list of {@link String}s
     * @return a list of {@link XmlOID}
     */
    private List<XmlOID> buildXmlOIDs(List<String> oids) {
        List<XmlOID> result = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(oids)) {
            for (String oid : oids) {
                XmlOID xmlOID = new XmlOID();
                xmlOID.setValue(oid);
                result.add(xmlOID);
            }
        }
        return result;
    }

    /**
     * Builds {@code XmlQcEuLimitValue}
     *
     * @param qcLimitValue {@link QCLimitValue}
     * @return {@link QCLimitValue}
     */
    public XmlQcEuLimitValue buildQcEuLimitValue(QCLimitValue qcLimitValue) {
        XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
        xmlQcEuLimitValue.setCurrency(qcLimitValue.getCurrency());
        xmlQcEuLimitValue.setAmount(qcLimitValue.getAmount());
        xmlQcEuLimitValue.setExponent(qcLimitValue.getExponent());
        return xmlQcEuLimitValue;
    }

    /**
     * Builds a deep copy of {@code XmlQcStatements}
     * NOTE: does not copy MRA content
     *
     * @param xmlQcStatements {@link XmlQcStatements} to copy
     * @return new {@link XmlQcStatements}
     */
    public XmlQcStatements copy(XmlQcStatements xmlQcStatements) {
        XmlQcStatements copy = new XmlQcStatements();
        copy.setOID(xmlQcStatements.getOID());
        copy.setDescription(xmlQcStatements.getDescription());
        copy.setCritical(xmlQcStatements.isCritical());
        if (xmlQcStatements.getQcCompliance() != null) {
            XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
            xmlQcCompliance.setPresent(xmlQcStatements.getQcCompliance().isPresent());
            copy.setQcCompliance(xmlQcCompliance);
        }
        if (xmlQcStatements.getQcEuLimitValue() != null) {
            XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
            xmlQcEuLimitValue.setAmount(xmlQcStatements.getQcEuLimitValue().getAmount());
            xmlQcEuLimitValue.setCurrency(xmlQcStatements.getQcEuLimitValue().getCurrency());
            xmlQcEuLimitValue.setExponent(xmlQcStatements.getQcEuLimitValue().getExponent());
            copy.setQcEuLimitValue(xmlQcEuLimitValue);
        }
        copy.setQcEuRetentionPeriod(xmlQcStatements.getQcEuRetentionPeriod());
        if (xmlQcStatements.getQcSSCD() != null) {
            XmlQcSSCD xmlQcSSCD = new XmlQcSSCD();
            xmlQcSSCD.setPresent(xmlQcStatements.getQcSSCD().isPresent());
            copy.setQcSSCD(xmlQcSSCD);
        }
        if (xmlQcStatements.getSemanticsIdentifier() != null) {
            XmlOID xmlSemanticIdentifier = new XmlOID();
            xmlSemanticIdentifier.setDescription(xmlQcStatements.getSemanticsIdentifier().getDescription());
            xmlSemanticIdentifier.setValue(xmlQcStatements.getSemanticsIdentifier().getValue());
            copy.setSemanticsIdentifier(xmlSemanticIdentifier);
        }
        if (xmlQcStatements.getPSD2QcInfo() != null) {
            XmlPSD2QcInfo xmlPSD2QcInfo = new XmlPSD2QcInfo();
            xmlPSD2QcInfo.setNcaId(xmlQcStatements.getPSD2QcInfo().getNcaId());
            xmlPSD2QcInfo.setNcaName(xmlQcStatements.getPSD2QcInfo().getNcaName());
            for (XmlRoleOfPSP roleOfPSP : xmlQcStatements.getPSD2QcInfo().getRolesOfPSP()) {
                XmlRoleOfPSP xmlRoleOfPSP = new XmlRoleOfPSP();
                xmlRoleOfPSP.setName(roleOfPSP.getName());
                xmlRoleOfPSP.setOid(roleOfPSP.getOid());
                xmlPSD2QcInfo.getRolesOfPSP().add(xmlRoleOfPSP);
            }
            copy.setPSD2QcInfo(xmlPSD2QcInfo);
        }
        for (XmlLangAndValue xmlLangAndValue : xmlQcStatements.getQcEuPDS()) {
            XmlLangAndValue xmlQcEuPDS = new XmlLangAndValue();
            xmlQcEuPDS.setLang(xmlLangAndValue.getLang());
            xmlQcEuPDS.setValue(xmlLangAndValue.getValue());
            copy.getQcEuPDS().add(xmlQcEuPDS);
        }
        for (XmlOID xmlOID : xmlQcStatements.getQcTypes()) {
            XmlOID xmlQcType = new XmlOID();
            xmlQcType.setDescription(xmlOID.getDescription());
            xmlQcType.setValue(xmlOID.getValue());
            copy.getQcTypes().add(xmlQcType);
        }
        copy.getQcCClegislation().addAll(xmlQcStatements.getQcCClegislation());
        for (XmlOID xmlOID : xmlQcStatements.getOtherOIDs()) {
            XmlOID xmlOtherOID = new XmlOID();
            xmlOtherOID.setDescription(xmlOID.getDescription());
            xmlOtherOID.setValue(xmlOID.getValue());
            copy.getOtherOIDs().add(xmlOtherOID);
        }
        return copy;
    }

}
