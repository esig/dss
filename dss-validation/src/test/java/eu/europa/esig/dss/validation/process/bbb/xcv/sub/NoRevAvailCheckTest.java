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
import eu.europa.esig.dss.diagnostic.jaxb.XmlAuthorityInformationAccess;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCRLDistributionPoints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFreshestCRL;
import eu.europa.esig.dss.diagnostic.jaxb.XmlNoRevAvail;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.NoRevAvailCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NoRevAvailCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlNoRevAvail xmlNoRevAvail = new XmlNoRevAvail();
        xmlNoRevAvail.setOID(CertificateExtensionEnum.NO_REVOCATION_AVAILABLE.getOid());
        xmlNoRevAvail.setPresent(true);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlNoRevAvail);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        NoRevAvailCheck nrac = new NoRevAvailCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        nrac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void ca() {
        XmlNoRevAvail xmlNoRevAvail = new XmlNoRevAvail();
        xmlNoRevAvail.setOID(CertificateExtensionEnum.NO_REVOCATION_AVAILABLE.getOid());
        xmlNoRevAvail.setPresent(true);

        XmlBasicConstraints xmlBasicConstraints = new XmlBasicConstraints();
        xmlBasicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        xmlBasicConstraints.setCA(true);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlNoRevAvail);
        xc.getCertificateExtensions().add(xmlBasicConstraints);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        NoRevAvailCheck nrac = new NoRevAvailCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        nrac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void crlDistributionPoints() {

        XmlNoRevAvail xmlNoRevAvail = new XmlNoRevAvail();
        xmlNoRevAvail.setOID(CertificateExtensionEnum.NO_REVOCATION_AVAILABLE.getOid());
        xmlNoRevAvail.setPresent(true);

        XmlCRLDistributionPoints xmlCRLDistributionPoints = new XmlCRLDistributionPoints();
        xmlCRLDistributionPoints.setOID(CertificateExtensionEnum.CRL_DISTRIBUTION_POINTS.getOid());
        xmlCRLDistributionPoints.getCrlUrl().add("http://crl.distribution.point");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlNoRevAvail);
        xc.getCertificateExtensions().add(xmlCRLDistributionPoints);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        NoRevAvailCheck nrac = new NoRevAvailCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        nrac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void deltaCrl() {
        XmlNoRevAvail xmlNoRevAvail = new XmlNoRevAvail();
        xmlNoRevAvail.setOID(CertificateExtensionEnum.NO_REVOCATION_AVAILABLE.getOid());
        xmlNoRevAvail.setPresent(true);

        XmlFreshestCRL xmlFreshestCRL = new XmlFreshestCRL();
        xmlFreshestCRL.setOID(CertificateExtensionEnum.FRESHEST_CRL.getOid());
        xmlFreshestCRL.getCrlUrl().add("http://crl.distribution.point");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlNoRevAvail);
        xc.getCertificateExtensions().add(xmlFreshestCRL);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        NoRevAvailCheck nrac = new NoRevAvailCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        nrac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void ocsp() {
        XmlNoRevAvail xmlNoRevAvail = new XmlNoRevAvail();
        xmlNoRevAvail.setOID(CertificateExtensionEnum.NO_REVOCATION_AVAILABLE.getOid());
        xmlNoRevAvail.setPresent(true);

        XmlAuthorityInformationAccess xmlAuthorityInformationAccess = new XmlAuthorityInformationAccess();
        xmlAuthorityInformationAccess.setOID(CertificateExtensionEnum.AUTHORITY_INFORMATION_ACCESS.getOid());
        xmlAuthorityInformationAccess.getOcspUrls().add("http://ocsp.access.point");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlNoRevAvail);
        xc.getCertificateExtensions().add(xmlAuthorityInformationAccess);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        NoRevAvailCheck nrac = new NoRevAvailCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        nrac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void ocspNoNoRevAvail() {
        XmlAuthorityInformationAccess xmlAuthorityInformationAccess = new XmlAuthorityInformationAccess();
        xmlAuthorityInformationAccess.setOID(CertificateExtensionEnum.AUTHORITY_INFORMATION_ACCESS.getOid());
        xmlAuthorityInformationAccess.getOcspUrls().add("http://ocsp.access.point");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlAuthorityInformationAccess);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        NoRevAvailCheck nrac = new NoRevAvailCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        nrac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
