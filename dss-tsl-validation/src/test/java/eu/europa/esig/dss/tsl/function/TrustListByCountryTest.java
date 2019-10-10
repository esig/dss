package eu.europa.esig.dss.tsl.function;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.tsl.function.TrustListByCountry;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

class TrustListByCountryTest {

    @Test
    void test() throws Exception {
        File fileToTest = new File("src/test/resources/fr.xml");
        
        TrustStatusListType trustStatusList = TrustedListFacade.newFacade().unmarshall(fileToTest);
        
        TrustListByCountry selector = new TrustListByCountry("lu");

        assertFalse(selector.test(trustStatusList));    
        
        selector = new TrustListByCountry("fr");

        assertTrue(selector.test(trustStatusList));    
        
        assertFalse(selector.test(null));
        
        selector = new TrustListByCountry((String)null);

        assertFalse(selector.test(trustStatusList));

        Set<String> testSet = new HashSet<String>();

        testSet.add("lu");
        testSet.add("pt");
        
        selector = new TrustListByCountry(testSet);
        
        assertFalse(selector.test(trustStatusList));

        testSet.add("fr");
        
        selector = new TrustListByCountry(testSet);
        
        assertTrue(selector.test(trustStatusList));        
    }

}