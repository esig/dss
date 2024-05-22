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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ServiceByMRAEnactedFilterTest {

    @Test
    public void noTSTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();
        assertTrue(Utils.isCollectionEmpty(filter.filter(new ArrayList<>())));
    }

    @Test
    public void enactedTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();

        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setEnactedMRA(true);

        assertEquals(1, filter.filter(Collections.singletonList(service)).size());
    }

    @Test
    public void notEnactedTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();

        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setEnactedMRA(false);

        assertEquals(0, filter.filter(Collections.singletonList(service)).size());
    }

    @Test
    public void noEnactedTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();

        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setEnactedMRA(null);

        assertEquals(0, filter.filter(Collections.singletonList(service)).size());
    }

}
