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
package eu.europa.esig.dss.validation.process.attestation.status.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.attestation.status.AttestationRevocationIssuerValidAtIssuanceTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttestationRevocationIssuerValidAtIssuanceTimeCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestationRevocationToken xmlAttestationRevocationToken = new XmlAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        Date currentTime = calendar.getTime();
        xmlAttestationRevocationToken.setIssuedAt(currentTime);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlCertificate = new XmlCertificate();
        calendar.add(Calendar.MONTH, -1);
        xmlCertificate.setNotBefore(calendar.getTime());
        calendar.add(Calendar.MONTH, 2);
        xmlCertificate.setNotAfter(calendar.getTime());
        xmlSigningCertificate.setCertificate(xmlCertificate);

        xmlAttestationRevocationToken.setSigningCertificate(xmlSigningCertificate);
        XmlSAV result = new XmlSAV();

        AttestationRevocationIssuerValidAtIssuanceTimeCheck asivaitc = new AttestationRevocationIssuerValidAtIssuanceTimeCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlAttestationRevocationToken), new LevelConstraintWrapper(constraint));
        asivaitc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void expiredTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestationRevocationToken xmlAttestationRevocationToken = new XmlAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        Date currentTime = calendar.getTime();
        xmlAttestationRevocationToken.setIssuedAt(currentTime);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlCertificate = new XmlCertificate();
        calendar.add(Calendar.MONTH, -6);
        xmlCertificate.setNotBefore(calendar.getTime());
        calendar.add(Calendar.MONTH, 2);
        xmlCertificate.setNotAfter(calendar.getTime());
        xmlSigningCertificate.setCertificate(xmlCertificate);

        xmlAttestationRevocationToken.setSigningCertificate(xmlSigningCertificate);
        XmlSAV result = new XmlSAV();

        AttestationRevocationIssuerValidAtIssuanceTimeCheck asivaitc = new AttestationRevocationIssuerValidAtIssuanceTimeCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlAttestationRevocationToken), new LevelConstraintWrapper(constraint));
        asivaitc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notYetValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestationRevocationToken xmlAttestationRevocationToken = new XmlAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        Date currentTime = calendar.getTime();
        xmlAttestationRevocationToken.setIssuedAt(currentTime);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlCertificate = new XmlCertificate();
        calendar.add(Calendar.MONTH, 6);
        xmlCertificate.setNotBefore(calendar.getTime());
        calendar.add(Calendar.MONTH, 2);
        xmlCertificate.setNotAfter(calendar.getTime());
        xmlSigningCertificate.setCertificate(xmlCertificate);

        xmlAttestationRevocationToken.setSigningCertificate(xmlSigningCertificate);
        XmlSAV result = new XmlSAV();

        AttestationRevocationIssuerValidAtIssuanceTimeCheck asivaitc = new AttestationRevocationIssuerValidAtIssuanceTimeCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlAttestationRevocationToken), new LevelConstraintWrapper(constraint));
        asivaitc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notSignCertTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestationRevocationToken xmlAttestationRevocationToken = new XmlAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        Date currentTime = calendar.getTime();
        xmlAttestationRevocationToken.setIssuedAt(currentTime);

        XmlSAV result = new XmlSAV();

        AttestationRevocationIssuerValidAtIssuanceTimeCheck asivaitc = new AttestationRevocationIssuerValidAtIssuanceTimeCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlAttestationRevocationToken), new LevelConstraintWrapper(constraint));
        asivaitc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}