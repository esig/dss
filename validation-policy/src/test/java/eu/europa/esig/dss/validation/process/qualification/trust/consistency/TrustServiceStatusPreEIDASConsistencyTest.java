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
package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustServiceStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrustServiceStatusPreEIDASConsistencyTest extends AbstractTrustServiceConsistencyTest {

    private final static TrustServiceCondition condition = new TrustServiceStatusPreEIDASConsistency();

    @Test
    public void testAccreditedPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.ACCREDITED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testSupervisionPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.SUPERVISION_CEASED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testGrantedPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.GRANTED.getUri());
        assertFalse(condition.isConsistent(service));
    }

    @Test
    public void testWithdrawnPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.WITHDRAWN.getUri());
        assertFalse(condition.isConsistent(service));
    }

    @Test
    public void testAccreditedPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.ACCREDITED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testSupervisionPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.SUPERVISION_CEASED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testGrantedPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.GRANTED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testWithdrawnPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.WITHDRAWN.getUri());
        assertTrue(condition.isConsistent(service));
    }

}
