package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CryptographicSuiteJsonFactoryTest {

    @Test
    void serviceLoaderTest() {
        FileDocument cryptoSuite = new FileDocument("src/test/resources/19312MachineReadable-fix.json");

        ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> factoryOptions = loader.iterator();

        CryptographicSuite cryptographicSuite = null;
        while (factoryOptions.hasNext()) {
            CryptographicSuiteFactory factory = factoryOptions.next();
            if (factory.isSupported(cryptoSuite)) {
                cryptographicSuite = factory.loadCryptographicSuite(cryptoSuite);
            }
        }
        assertNotNull(cryptographicSuite);
    }

    @Test
    void serviceLoaderDefaultTest() {
        ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> factoryOptions = loader.iterator();

        CryptographicSuite cryptographicSuite = null;
        if (factoryOptions.hasNext()) {
            CryptographicSuiteFactory factory = factoryOptions.next();
            cryptographicSuite = factory.loadDefaultCryptographicSuite();
        }
        assertNotNull(cryptographicSuite);
    }

}
