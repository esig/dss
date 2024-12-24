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
package eu.europa.esig.dss.enumerations;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class TokenExtractionStrategyTest {

    @Test
    void valuesTest() {
        List<TokenExtractionStrategy> strategies = new ArrayList<>();
        List<Boolean> possibleBooleans = Arrays.asList(Boolean.TRUE, Boolean.FALSE);
        for (boolean includeCertificates : possibleBooleans) {
            for (boolean includeTimestamps : possibleBooleans) {
                for (boolean includeRevocationData : possibleBooleans) {
                    for (boolean includeEvidenceRecords : possibleBooleans) {
                        TokenExtractionStrategy strategy = TokenExtractionStrategy.fromParameters(
                                includeCertificates, includeTimestamps, includeRevocationData, includeEvidenceRecords);
                        assertNotNull(strategy);
                        assertFalse(strategies.contains(strategy));
                        strategies.add(strategy);
                    }
                }
            }
        }
        assertEquals(16, strategies.size());
    }

}
