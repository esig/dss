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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.utils.Utils;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServiceByMRAEquivalenceStartingDateFilterTest {

    private static final Date DATE1 = DatatypeConverter.parseDateTime("2015-07-01T00:00:00-00:00").getTime();
    private static final Date DATE2 = DatatypeConverter.parseDateTime("2016-07-01T00:00:00-00:00").getTime();
    private static final Date DATE3 = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

    @Test
    void noTSTest() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);
        assertTrue(Utils.isCollectionEmpty(filter.filter(new ArrayList<>())));
    }

    @Test
    void testValid() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);

        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertTrue(filter.isAcceptable(service));
    }

    @Test
    void testInvalid() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);

        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE3);

        assertFalse(filter.isAcceptable(service));
    }

    @Test
    void testSameTime() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE1);

        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertTrue(filter.isAcceptable(service));
    }

    @Test
    void testNoDate() {
        ServiceByDateFilter filter = new ServiceByDateFilter(null);

        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertFalse(filter.isAcceptable(service));
    }

    @Test
    void testNoStartingDate() {
        ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

        TrustServiceWrapper service = new TrustServiceWrapper();

        assertFalse(filter.isAcceptable(service));
    }

}
