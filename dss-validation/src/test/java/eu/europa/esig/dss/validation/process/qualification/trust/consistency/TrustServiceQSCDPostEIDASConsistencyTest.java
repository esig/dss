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

class TrustServiceQSCDPostEIDASConsistencyTest extends AbstractTrustServiceConsistencyTest {

    private TrustServiceCondition condition = new TrustServiceQSCDPostEIDASConsistency();

    @Test
    void postEidasQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void postEidasNoQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void postEidasSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
        assertFalse(condition.isConsistent(service));
    }

    @Test
    void postEidasNoSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
        assertFalse(condition.isConsistent(service));
    }

    @Test
    void postEidasQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri(), ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void postEidasNoQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri(), ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void preEidasQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void preEidasNoQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void preEidasSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void preEidasNoSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void preEidasQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri(), ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    void preEidasNoQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri(), ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

}
