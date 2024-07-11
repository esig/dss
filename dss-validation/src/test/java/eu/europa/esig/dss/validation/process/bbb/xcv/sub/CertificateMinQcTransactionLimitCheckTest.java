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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateMinQcTransactionLimitCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateMinQcTransactionLimitCheckTest extends AbstractTestCheck {

    @Test
    void validTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlQcEuLimitValue xmlQCEuLimitValue = new XmlQcEuLimitValue();
        xmlQCEuLimitValue.setAmount(1000);
        xmlQCEuLimitValue.setExponent(3);
        xmlQcStatements.setQcEuLimitValue(xmlQCEuLimitValue);

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(500000);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sameNumberTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlQcEuLimitValue xmlQCEuLimitValue = new XmlQcEuLimitValue();
        xmlQCEuLimitValue.setAmount(1000);
        xmlQCEuLimitValue.setExponent(3);
        xmlQcStatements.setQcEuLimitValue(xmlQCEuLimitValue);

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(1000000);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlQcEuLimitValue xmlQCEuLimitValue = new XmlQcEuLimitValue();
        xmlQCEuLimitValue.setAmount(1000);
        xmlQCEuLimitValue.setExponent(3);
        xmlQcStatements.setQcEuLimitValue(xmlQCEuLimitValue);

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(5000000);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void qcLimitValueNotPresentTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(500000);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void qcStatementsNotPresentTest() throws Exception {
        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(500000);

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
