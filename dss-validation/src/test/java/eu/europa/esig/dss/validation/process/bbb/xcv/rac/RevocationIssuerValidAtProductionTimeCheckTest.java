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
package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationIssuerValidAtProductionTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RevocationIssuerValidAtProductionTimeCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setProductionDate(new Date());
        xmlRevocation.setType(RevocationType.OCSP);

        Calendar calendar = Calendar.getInstance();
        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(xmlCertificate);
        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlRAC result = new XmlRAC();
        RevocationIssuerValidAtProductionTimeCheck rivptc = new RevocationIssuerValidAtProductionTimeCheck(
                i18nProvider, result, new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rivptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setProductionDate(new Date());
        xmlRevocation.setType(RevocationType.OCSP);

        Calendar calendar = Calendar.getInstance();
        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(xmlCertificate);
        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlRAC result = new XmlRAC();
        RevocationIssuerValidAtProductionTimeCheck rivptc = new RevocationIssuerValidAtProductionTimeCheck(
                i18nProvider, result, new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rivptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidCrlTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setProductionDate(new Date());
        xmlRevocation.setType(RevocationType.CRL);

        Calendar calendar = Calendar.getInstance();
        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(xmlCertificate);
        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlRAC result = new XmlRAC();
        RevocationIssuerValidAtProductionTimeCheck rivptc = new RevocationIssuerValidAtProductionTimeCheck(
                i18nProvider, result, new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rivptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void validProducedAtTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setProductionDate(calendar.getTime());
        xmlRevocation.setType(RevocationType.OCSP);

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setNotBefore(calendar.getTime());
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(xmlCertificate);
        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlRAC result = new XmlRAC();
        RevocationIssuerValidAtProductionTimeCheck rivptc = new RevocationIssuerValidAtProductionTimeCheck(
                i18nProvider, result, new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rivptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void noIssuerTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setProductionDate(new Date());
        xmlRevocation.setType(RevocationType.OCSP);

        XmlRAC result = new XmlRAC();
        RevocationIssuerValidAtProductionTimeCheck rivptc = new RevocationIssuerValidAtProductionTimeCheck(
                i18nProvider, result, new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rivptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
