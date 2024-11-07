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
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSupportedCriticalExtensionsCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateSupportedCriticalExtensionsCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        constraint.getId().add(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notCriticalTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        XmlCertificateExtension certificateExtensionNotCritical = new XmlCertificateExtension();
        certificateExtensionNotCritical.setOID(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
        certificateExtensionNotCritical.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionNotCritical);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        constraint.getId().add(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notCriticalExtensionsTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        XmlCertificateExtension certificateExtensionNotCritical = new XmlCertificateExtension();
        certificateExtensionNotCritical.setOID(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
        certificateExtensionNotCritical.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionNotCritical);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.KEY_USAGE.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notExtensionsTest() {
        XmlCertificate xc = new XmlCertificate();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.KEY_USAGE.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void noConstraintsDefinedTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noConstraintsDefinedNoCriticalTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }


}
