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
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralSubtree;
import eu.europa.esig.dss.diagnostic.jaxb.XmlNameConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.GeneralNameType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNameConstraintsCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateNameConstraintsCheckTest extends AbstractTestCheck {

    @Test
    void permittedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Production Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesMissingAttribute() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesValidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesInvalidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Production Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesCADefinedValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesCADefinedInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesValidCAOverwrite() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1,CN=Valid DN nameConstraints EE Certificate Test1");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesValidCARemoveProp() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,OU=permittedSubtree1");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesValidCAAddProp() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1,CN=Invalid");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void multiplePermittedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=permittedSubtree2");
        nameConstraints.getPermittedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void multiplePermittedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=permittedSubtree2");
        nameConstraints.getPermittedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree3,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void emptyPermittedSubtrees() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }
    @Test
    void permittedSubtreesEmptyCertDN() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesMissingAttribute() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesValidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Production Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesInvalidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesCADefinedValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesCADefinedInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesValidCAAdd() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Production Certificates,OU=excludedSubtree1");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesValidCAAddProp() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1,CN=Invalid");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void multipleExcludedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=excludedSubtree2");
        nameConstraints.getExcludedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree3,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void multipleExcludedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=excludedSubtree2");
        nameConstraints.getExcludedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree2,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void emptyExcludedSubtrees() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesEmptyCertDN() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedAndExcludedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);

        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedAndExcludedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);

        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesSubAltNameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US"));
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test2,OU=permittedSubtree1,O=Test Certificates,C=US"));
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesSubAltNameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US"));
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US"));
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesSubAltNameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US"));
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US"));
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesSubAltNameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US"));
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US"));
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesSubAltNameWithNotRDNValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US"));
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.RFC822_NAME,
                "endentity@test.com"));
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesSubAltNameWithNotRDNInvalidType() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.OTHER_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US"));
        subjectAlternativeNames.getSubjectAlternativeName().add(getXmlGeneralName(GeneralNameType.DIRECTORY_NAME,
                "CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US"));
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesWithEscapedChar() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1\\,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesWithEscapedChar() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1\\,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesStartFromComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue(",CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesEndWithComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US,");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesStartFromComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue(",CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesEndWithComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US,");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesEnrichInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("OU=permittedSubtree2,OU=permittedSubtree1,O=Test Certificates,C=US");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Invalid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesConflictInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("OU=permittedSubtree2,O=Test Certificates,C=US");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Invalid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesEmptyDNValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("OU=permittedSubtree2,O=Test Certificates,C=US");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreeMissedNameConstraintValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesURIValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesURIInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc2.es");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesURIValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc2.es");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc2.es");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesURIInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("www.upc.edu");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesURIDomainValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue(".testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("http://testserver.testcertificates.gov/index.html");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesURIDomainInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue(".testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("http://testcertificates.gov/invalid.html");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesURIDomainValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("invalidcertificates.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("http://testserver.invalidcertificates.gov/index.html");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesURIDomainInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("invalidcertificates.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        xmlGeneralSubtree.setValue("ftp://invalidcertificates.gov:21/test37/");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesRFC822NameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@testcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesRFC822NameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@mailserver.testcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesRFC822NameDomainInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@testcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesRFC822NameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("testcertificates.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@mailserver.testcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesRFC822NameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("testcertificates.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@testcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesDNSNameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("testserver.testcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesDNSNameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("testserver.invalidcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesDNSNameMixedInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("mytestcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesDNSNameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("invalidcertificates.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("testserver.testcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesDNSNameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("invalidcertificates.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DNS_NAME);
        xmlGeneralSubtree.setValue("invalidcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesDNAndRFC822NameInvalidDN() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree dnSubtree = new XmlGeneralSubtree();
        dnSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        dnSubtree.setValue("OU=permittedSubtree1,O=Test Certificates,C=US");
        nameConstraints.getPermittedSubtrees().add(dnSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree rfc822Subtree = new XmlGeneralSubtree();
        rfc822Subtree.setType(GeneralNameType.RFC822_NAME);
        rfc822Subtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(rfc822Subtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        rfc822Subtree = new XmlGeneralSubtree();
        rfc822Subtree.setType(GeneralNameType.RFC822_NAME);
        rfc822Subtree.setValue("Test@invalidcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(rfc822Subtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesDNAndRFC822NameInvalidRFC822() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree dnSubtree = new XmlGeneralSubtree();
        dnSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        dnSubtree.setValue("OU=permittedSubtree1,O=Test Certificates,C=US");
        nameConstraints.getPermittedSubtrees().add(dnSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree rfc822Subtree = new XmlGeneralSubtree();
        rfc822Subtree.setType(GeneralNameType.RFC822_NAME);
        rfc822Subtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(rfc822Subtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        rfc822Subtree = new XmlGeneralSubtree();
        rfc822Subtree.setType(GeneralNameType.RFC822_NAME);
        rfc822Subtree.setValue("Test@invalidcertificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(rfc822Subtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesDNAndRFC822NameValidRFC822Missed() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree dnSubtree = new XmlGeneralSubtree();
        dnSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        dnSubtree.setValue("OU=permittedSubtree1,O=Test Certificates,C=US");
        nameConstraints.getPermittedSubtrees().add(dnSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree rfc822Subtree = new XmlGeneralSubtree();
        rfc822Subtree.setType(GeneralNameType.RFC822_NAME);
        rfc822Subtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(rfc822Subtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesDNAndRFC822NameInvalidWithDNEmailAddress() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree dnSubtree = new XmlGeneralSubtree();
        dnSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        dnSubtree.setValue("OU=permittedSubtree1,O=Test Certificates,C=US");
        nameConstraints.getPermittedSubtrees().add(dnSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree rfc822Subtree = new XmlGeneralSubtree();
        rfc822Subtree.setType(GeneralNameType.RFC822_NAME);
        rfc822Subtree.setValue("testcertificates.gov");
        nameConstraints.getPermittedSubtrees().add(rfc822Subtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("1.2.840.113549.1.9.1=#1620546573743239454540696e76616c69646365727469666963617465732e676f76,CN=Invalid DN and RFC822 nameConstraints EE Certificate Test,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesIPAddressValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#c0a80000ffffff00");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#c0a80005");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesIPAddressInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#c0a80000ffff00ff");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#c0a80005");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesIPAddressAllValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#0000000000000000");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#C0000200");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesIPAddressNoneInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#FFFFFFFFFFFFFFFF");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#C0000200");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesIPAddressNoneValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#FFFFFFFFFFFFFFFF");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#C0000200");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesIPAddressAllInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#0000000000000000");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralSubtree.setValue("#C0000200");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesRFC822NameIntersectValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".test.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@certificates.test.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void permittedSubtreesRFC822NameIntersectInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".test.gov");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@certificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesRFC822NameUnionValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".test.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@certificates.test.eu");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void excludedSubtreesRFC822NameUnionInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue(".test.gov");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.RFC822_NAME);
        xmlGeneralSubtree.setValue("Test@certificates.gov");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralSubtree);
        signCertificate.getCertificateExtensions().add(xmlSubjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    private XmlGeneralName getXmlGeneralName(GeneralNameType type, String value) {
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(type);
        xmlGeneralName.setValue(value);
        return xmlGeneralName;
    }

}
