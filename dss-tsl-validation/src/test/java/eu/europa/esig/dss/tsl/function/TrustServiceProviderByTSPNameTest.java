package eu.europa.esig.dss.tsl.function;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.tsl.function.TrustServiceProviderByTSPName;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

class TrustServiceProviderByTSPNameTest {

    @Test
    void test() throws Exception {
        File fileToTest = new File("src/test/resources/fr.xml");
        
        TrustStatusListType trustStatusList = TrustedListFacade.newFacade().unmarshall(fileToTest);

        
        TrustServiceProviderListType trustServiceProviderList = trustStatusList.getTrustServiceProviderList();
        List<TSPType> trustServiceProvider = trustServiceProviderList.getTrustServiceProvider();
        
        TSPType tspType = trustServiceProvider.get(0);
        
        TrustServiceProviderByTSPName selector = new TrustServiceProviderByTSPName("test");

        assertFalse(selector.test(tspType));
        
        selector = new TrustServiceProviderByTSPName("Agence Nationale des Titres Sécurisés");
        
        assertTrue(selector.test(tspType));
        
        assertFalse(selector.test(null));
        
        selector = new TrustServiceProviderByTSPName(null);
        
        assertFalse(selector.test(tspType));
        
        assertFalse(selector.test(null));
        
    }

}