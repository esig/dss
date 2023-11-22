package eu.europa.esig.dss.enumerations;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TokenExtractionStrategyTest {

    @Test
    public void valuesTest() {
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
