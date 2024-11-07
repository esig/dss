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
package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustServiceQualifiersKnownConsistencyTest extends AbstractTrustServiceConsistencyTest {

    private static final TrustServiceCondition condition = new TrustServiceQualifiersKnownConsistency();

    @Test
    void testQCWithSSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCNoSSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCSSCDStatusAsInCert() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_SSCD_STATUS_AS_IN_CERT.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCWithQSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCNoQSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCQSCDStatusAsInCert() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCQSCDManagedOnBehalf() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCForLegalPerson() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_LEGAL_PERSON.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCForESig() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_ESIG.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCForESeal() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_ESEAL.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCForWSA() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_WSA.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testNotQualified() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.NOT_QUALIFIED.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testQCStatement() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_STATEMENT.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testKnownQualifierCombination() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void testNotKnownQualifier() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList("custom-uri"));
        assertFalse(condition.isConsistent(service));
    }

    @Test
    void testNotKnownQualifierCombination() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri(), "custom-uri"));
        assertFalse(condition.isConsistent(service));
    }

}
