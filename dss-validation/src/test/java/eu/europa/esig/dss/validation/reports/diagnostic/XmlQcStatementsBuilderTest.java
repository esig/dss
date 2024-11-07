/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2QcInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcSSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRoleOfPSP;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;

class XmlQcStatementsBuilderTest {

    @Test
    void copyTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        xmlQcStatements.setDescription(CertificateExtensionEnum.QC_STATEMENTS.getDescription());
        xmlQcStatements.setCritical(true);

        XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
        xmlQcCompliance.setPresent(true);
        xmlQcStatements.setQcCompliance(xmlQcCompliance);

        XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
        xmlQcEuLimitValue.setExponent(10);
        xmlQcEuLimitValue.setCurrency("EUR");
        xmlQcEuLimitValue.setAmount(10000);
        xmlQcStatements.setQcEuLimitValue(xmlQcEuLimitValue);

        xmlQcStatements.setQcEuRetentionPeriod(5);

        XmlQcSSCD xmlQcSSCD = new XmlQcSSCD();
        xmlQcSSCD.setPresent(true);
        xmlQcStatements.setQcSSCD(xmlQcSSCD);

        XmlLangAndValue xmlQcEuPDS = new XmlLangAndValue();
        xmlQcEuPDS.setLang("en");
        xmlQcEuPDS.setValue("100");
        xmlQcStatements.getQcEuPDS().add(xmlQcEuPDS);

        XmlOID xmlQcType = new XmlOID();
        xmlQcType.setValue(QCTypeEnum.QCT_ESIGN.getOid());
        xmlQcType.setDescription(QCTypeEnum.QCT_ESIGN.getDescription());
        xmlQcStatements.getQcTypes().add(xmlQcType);

        xmlQcStatements.getQcCClegislation().add("UA");

        XmlOID xmlSemanticIdentifier = new XmlOID();
        xmlSemanticIdentifier.setValue(SemanticsIdentifier.qcsSemanticsIdEIDASLegal.getOid());
        xmlSemanticIdentifier.setDescription(SemanticsIdentifier.qcsSemanticsIdEIDASLegal.getDescription());
        xmlQcStatements.setSemanticsIdentifier(xmlSemanticIdentifier);

        XmlPSD2QcInfo xmlPSD2QcInfo = new XmlPSD2QcInfo();
        xmlPSD2QcInfo.setNcaId("ID");
        xmlPSD2QcInfo.setNcaName("Name");
        XmlRoleOfPSP xmlRoleOfPSP = new XmlRoleOfPSP();
        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue("10.2.5.3");
        xmlRoleOfPSP.setOid(xmlOID);
        xmlRoleOfPSP.setName("Role name");
        xmlPSD2QcInfo.getRolesOfPSP().add(xmlRoleOfPSP);
        xmlQcStatements.setPSD2QcInfo(xmlPSD2QcInfo);

        XmlOID xmlOtherOID = new XmlOID();
        xmlOtherOID.setValue("1.2.3.6");
        xmlOtherOID.setDescription("Other OID");
        xmlQcStatements.getOtherOIDs().add(xmlOtherOID);

        XmlQcStatements copy = new XmlQcStatementsBuilder().copy(xmlQcStatements);
        assertNotSame(xmlQcStatements, copy);

        assertEquals(xmlQcStatements.getOID(), copy.getOID());
        assertEquals(xmlQcStatements.getDescription(), copy.getDescription());
        assertEquals(xmlQcStatements.isCritical(), copy.isCritical());

        assertNotNull(copy.getQcCompliance());
        assertEquals(xmlQcStatements.getQcCompliance().isPresent(), copy.getQcCompliance().isPresent());

        assertNotNull(copy.getQcEuLimitValue());
        assertEquals(xmlQcStatements.getQcEuLimitValue().getAmount(), copy.getQcEuLimitValue().getAmount());
        assertEquals(xmlQcStatements.getQcEuLimitValue().getCurrency(), copy.getQcEuLimitValue().getCurrency());
        assertEquals(xmlQcStatements.getQcEuLimitValue().getExponent(), copy.getQcEuLimitValue().getExponent());

        assertEquals(xmlQcStatements.getQcEuRetentionPeriod(), copy.getQcEuRetentionPeriod());

        assertNotNull(copy.getQcSSCD());
        assertEquals(xmlQcStatements.getQcSSCD().isPresent(), copy.getQcSSCD().isPresent());

        assertEquals(xmlQcStatements.getQcEuPDS().size(), copy.getQcEuPDS().size());
        assertEquals(xmlQcStatements.getQcEuPDS().get(0).getLang(), copy.getQcEuPDS().get(0).getLang());
        assertEquals(xmlQcStatements.getQcEuPDS().get(0).getValue(), copy.getQcEuPDS().get(0).getValue());

        assertEquals(xmlQcStatements.getQcTypes().size(), copy.getQcTypes().size());
        assertEquals(xmlQcStatements.getQcTypes().get(0).getValue(), copy.getQcTypes().get(0).getValue());
        assertEquals(xmlQcStatements.getQcTypes().get(0).getDescription(), copy.getQcTypes().get(0).getDescription());

        assertEquals(xmlQcStatements.getQcCClegislation().size(), copy.getQcCClegislation().size());
        assertEquals(xmlQcStatements.getQcCClegislation().get(0), copy.getQcCClegislation().get(0));

        assertNotNull(copy.getSemanticsIdentifier());
        assertEquals(xmlQcStatements.getSemanticsIdentifier().getValue(), copy.getSemanticsIdentifier().getValue());
        assertEquals(xmlQcStatements.getSemanticsIdentifier().getDescription(), copy.getSemanticsIdentifier().getDescription());

        assertNotNull(copy.getPSD2QcInfo());
        assertEquals(xmlQcStatements.getPSD2QcInfo().getNcaId(), copy.getPSD2QcInfo().getNcaId());
        assertEquals(xmlQcStatements.getPSD2QcInfo().getNcaName(), copy.getPSD2QcInfo().getNcaName());
        assertEquals(xmlQcStatements.getPSD2QcInfo().getRolesOfPSP().size(), copy.getPSD2QcInfo().getRolesOfPSP().size());
        assertEquals(xmlQcStatements.getPSD2QcInfo().getRolesOfPSP().get(0).getName(), copy.getPSD2QcInfo().getRolesOfPSP().get(0).getName());
        assertEquals(xmlQcStatements.getPSD2QcInfo().getRolesOfPSP().get(0).getOid().getDescription(), copy.getPSD2QcInfo().getRolesOfPSP().get(0).getOid().getDescription());
        assertEquals(xmlQcStatements.getPSD2QcInfo().getRolesOfPSP().get(0).getOid().getValue(), copy.getPSD2QcInfo().getRolesOfPSP().get(0).getOid().getValue());

        assertEquals(xmlQcStatements.getOtherOIDs().size(), copy.getOtherOIDs().size());
        assertEquals(xmlQcStatements.getOtherOIDs().get(0).getValue(), copy.getOtherOIDs().get(0).getValue());
        assertEquals(xmlQcStatements.getOtherOIDs().get(0).getDescription(), copy.getOtherOIDs().get(0).getDescription());
    }

}
