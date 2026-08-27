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
package eu.europa.esig.dss.lote.dto;

import eu.europa.esig.dss.model.lote.TrustedEntityServiceStatusAndInformationExtensions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TrustedEntityServiceStatusAndInformationExtensionsTest {
    
    @Test
    void test() {
        Date startDate = new Date(1704067200000L); // 2024-01-01 UTC
        Date endDate = new Date(1735689600000L);   // 2025-01-01 UTC

        Map<String, List<String>> names = Collections.singletonMap("en", Collections.singletonList("PID Provider Trusted Entity"));
        List<String> supplyPoints = Arrays.asList("https://pid.example.eu/pid-providers", "https://pid.example.eu/pid-providers-alt");

        TrustedEntityServiceStatusAndInformationExtensions status =
                new TrustedEntityServiceStatusAndInformationExtensions.ServiceStatusAndInformationExtensionsBuilder()
                        .setNames(names)
                        .setType("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList")
                        .setStatus("http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU")
                        .setServiceSupplyPoints(supplyPoints)
                        .setStartDate(startDate)
                        .setEndDate(endDate)
                        .build();

        assertEquals(names, status.getNames());
        assertEquals("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList", status.getType());
        assertEquals("http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU", status.getStatus());
        assertEquals(supplyPoints, status.getServiceSupplyPoints());
        assertEquals(startDate, status.getStartDate());
        assertEquals(endDate, status.getEndDate());
    }

    @Test
    void nullTest() {
        TrustedEntityServiceStatusAndInformationExtensions status =
                new TrustedEntityServiceStatusAndInformationExtensions.ServiceStatusAndInformationExtensionsBuilder()
                        .build();

        assertNull(status.getNames());
        assertNull(status.getType());
        assertNull(status.getStatus());
        assertNull(status.getServiceSupplyPoints());
        assertNull(status.getStartDate());
        assertNull(status.getEndDate());
    }

    @Test
    void copyTest() {
        Date startDate = new Date(1704067200000L);
        Date endDate = new Date(1735689600000L);

        Map<String, List<String>> names = Collections.singletonMap("en", Collections.singletonList("PID Provider Trusted Entity"));
        List<String> supplyPoints = Arrays.asList("https://pid.example.eu/pid-providers", "https://pid.example.eu/pid-providers-alt");

        TrustedEntityServiceStatusAndInformationExtensions original =
                new TrustedEntityServiceStatusAndInformationExtensions.ServiceStatusAndInformationExtensionsBuilder()
                        .setNames(names)
                        .setType("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList")
                        .setStatus("http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU")
                        .setServiceSupplyPoints(supplyPoints)
                        .setStartDate(startDate)
                        .setEndDate(endDate)
                        .build();

        TrustedEntityServiceStatusAndInformationExtensions copy =
                new TrustedEntityServiceStatusAndInformationExtensions.ServiceStatusAndInformationExtensionsBuilder(original)
                        .build();

        assertEquals(original.getNames(), copy.getNames());
        assertEquals(original.getType(), copy.getType());
        assertEquals(original.getStatus(), copy.getStatus());
        assertEquals(original.getServiceSupplyPoints(), copy.getServiceSupplyPoints());
        assertEquals(original.getStartDate(), copy.getStartDate());
        assertEquals(original.getEndDate(), copy.getEndDate());
    }

    @Test
    void nullBuilderTest() {
        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> new TrustedEntityServiceStatusAndInformationExtensions(null));
        assertEquals("ServiceStatusAndInformationExtensionsBuilder cannot be null!",
                exception.getMessage());
    }
    
}
