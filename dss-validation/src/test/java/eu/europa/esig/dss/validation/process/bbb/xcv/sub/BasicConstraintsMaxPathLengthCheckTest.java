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
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.BasicConstraintsMaxPathLengthCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BasicConstraintsMaxPathLengthCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        rootCertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notDefinedCheck() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        rootCertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void selfSignedTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        rootCertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void longChainTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void longChainEnforcedTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(2);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void longChainInvalidTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void decreasingDepthTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(2);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void decreasingDepthValidTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(3);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void increasingDepthTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void oneCertTest() {
        XmlCertificate caCertificate = new XmlCertificate();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void oneCertCATest() {
        XmlCertificate caCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void oneCertSelfSignedTest() {
        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void oneCertSelfSignedCATest() {
        XmlCertificate caCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);
        caCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
