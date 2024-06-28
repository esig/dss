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
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuerNameCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateIssuerNameCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test2,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void diffOrder() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("OU=permittedSubtree1,CN=Valid DN nameConstraints CA Certificate Test1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void missedAttr() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void selfSignedValid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        signingCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void selfSignedInvalid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        signingCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void sameDNNotSelfSignedValid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sameDNNotSelfSignedInvalid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}