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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcEuLimitValueCurrencyCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateQcEuLimitValueCurrencyCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
        xmlQcEuLimitValue.setCurrency("EUR");
        xmlQcStatements.setQcEuLimitValue(xmlQcEuLimitValue);

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("EUR");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
        xmlQcEuLimitValue.setCurrency("EUR");
        xmlQcStatements.setQcEuLimitValue(xmlQcEuLimitValue);

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("AUD");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void qcLimitValueNotPresentTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("EUR");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void qcStatementsNotPresentTest() {
        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("EUR");

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
