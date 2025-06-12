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
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationHasInformationAboutCertificateCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RevocationHasInformationAboutCertificateCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(new Date());

        Calendar calendar = Calendar.getInstance();
        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -2);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validSameTimeTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(new Date());

        Calendar calendar = Calendar.getInstance();
        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredOnCRLsTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, -2);
        xmlRevocation.setExpiredCertsOnCRL(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_CRL,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getExpiredCertsOnCRL()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void invalidExpiredOnCRLsTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, -2);
        xmlRevocation.setExpiredCertsOnCRL(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -2);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getExpiredCertsOnCRL()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredOnCRLsAndThisUpdateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, -1);
        xmlRevocation.setExpiredCertsOnCRL(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 3);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validNoExpiredOnCRLsButThisUpdateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlRevocation.setExpiredCertsOnCRL(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -2);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 4);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validArchiveCutOffTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, -2);
        xmlRevocation.setArchiveCutOff(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_OCSP,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getArchiveCutOff()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void invalidArchiveCutOffTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, -2);
        xmlRevocation.setArchiveCutOff(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -2);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getArchiveCutOff()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validArchiveCutOffAndThisUpdateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, -1);
        xmlRevocation.setArchiveCutOff(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 3);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validNoArchiveCutOffButThisUpdateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlRevocation.setArchiveCutOff(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -2);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 4);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredCertsRevocationInfoTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, -2);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_TL,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlTrustService.getExpiredCertsRevocationInfo()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void invalidExpiredCertsRevocationInfoTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, -2);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -2);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
                ValidationProcessUtils.getFormattedDate(xmlTrustService.getExpiredCertsRevocationInfo()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredCertsRevocationInfoAndThisUpdateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, -1);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 3);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validNoExpiredCertsRevocationIndoButThisUpdateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, 1);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -2);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 4);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredCertsRevocationInfoAndValidExpiredCertsOnCRLsTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, -2);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        calendar.add(Calendar.MONTH, 1);
        xmlRevocation.setExpiredCertsOnCRL(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_CRL,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getExpiredCertsOnCRL()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void invalidExpiredCertsRevocationInfoAndValidExpiredCertsOnCRLsTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, 1);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        calendar.add(Calendar.YEAR, -3);
        xmlRevocation.setExpiredCertsOnCRL(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_CRL,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getExpiredCertsOnCRL()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredCertsRevocationInfoAndInvalidExpiredCertsOnCRLsTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, -2);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        calendar.add(Calendar.YEAR, 1);
        xmlRevocation.setExpiredCertsOnCRL(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -5);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getExpiredCertsOnCRL()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredCertsRevocationInfoAndValidArchiveCutOffTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, -2);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        calendar.add(Calendar.MONTH, 1);
        xmlRevocation.setArchiveCutOff(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_OCSP,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getArchiveCutOff()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void invalidExpiredCertsRevocationInfoAndValidArchiveCutOffTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, 1);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        calendar.add(Calendar.YEAR, -3);
        xmlRevocation.setArchiveCutOff(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_OCSP,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getArchiveCutOff()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

    @Test
    void validExpiredCertsRevocationInfoAndInvalidArchiveCutOffTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        XmlCertificate xmlRevocationIssuer = new XmlCertificate();

        XmlTrustService xmlTrustService = new XmlTrustService();
        calendar.add(Calendar.YEAR, -2);
        xmlTrustService.setExpiredCertsRevocationInfo(calendar.getTime());

        XmlTrustServiceProvider xmlTrustServiceProvider = new XmlTrustServiceProvider();
        xmlTrustServiceProvider.getTrustServices().add(xmlTrustService);

        xmlRevocationIssuer.getTrustServiceProviders().add(xmlTrustServiceProvider);
        xmlSigningCertificate.setCertificate(xmlRevocationIssuer);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        calendar.add(Calendar.YEAR, 1);
        xmlRevocation.setArchiveCutOff(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -5);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationHasInformationAboutCertificateCheck rihiacc =
                new RevocationHasInformationAboutCertificateCheck(i18nProvider, result,
                        new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rihiacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
                ValidationProcessUtils.getFormattedDate(xmlRevocation.getArchiveCutOff()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(xmlCertificate.getNotAfter())), constraints.get(0).getAdditionalInfo());
    }

}
