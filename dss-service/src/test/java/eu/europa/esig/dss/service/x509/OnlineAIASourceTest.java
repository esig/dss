package eu.europa.esig.dss.service.x509;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.x509.AIASource;
import eu.europa.esig.dss.spi.x509.OnlineAIASource;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collection;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OnlineAIASourceTest {

    private static CertificateToken certificateWithAIA;

    @BeforeAll
    public static void init() {
        certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
        assertNotNull(certificateWithAIA);
    }

    @Test
    public void testLoadIssuer() {
        AIASource aiaSource = new OnlineAIASource();
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificateWithAIA);
        assertTrue(Utils.isCollectionNotEmpty(issuers));
        boolean foundIssuer = false;
        for (CertificateToken issuer : issuers) {
            if (certificateWithAIA.isSignedBy(issuer)) {
                foundIssuer = true;
            }
        }
        assertTrue(foundIssuer);
    }

    @Test
    public void setNullDataLoaderTest() {
        OnlineAIASource aiaSource = new OnlineAIASource();
        Exception exception = assertThrows(NullPointerException.class, () -> aiaSource.setDataLoader(null));
        assertEquals("dataLoader cannot be null!", exception.getMessage());
    }

    @Test
    public void emptyAcceptedProtocolsTest() {
        OnlineAIASource aiaSource = new OnlineAIASource();
        aiaSource.setAcceptedProtocols(Collections.emptySet());
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificateWithAIA);
        assertTrue(Utils.isCollectionEmpty(issuers));
    }

    @Test
    public void testLoadIssuerNoAIA() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.crt"));
        OnlineAIASource aiaSource = new OnlineAIASource();
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificate);
        assertTrue(Utils.isCollectionEmpty(issuers));
        assertTrue(certificate.isCA());
    }

    @Test
    public void acceptedProtocolsTest() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));
        MockCommonsDataLoader dataLoader = new MockCommonsDataLoader();

        OnlineAIASource aiaSource = new OnlineAIASource(dataLoader);

        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificate);
        assertEquals(1, issuers.size());
        assertEquals(3, dataLoader.counter);

        dataLoader = new MockCommonsDataLoader();
        aiaSource.setDataLoader(dataLoader);
        aiaSource.setAcceptedProtocols(Collections.singletonList(Protocol.HTTP));

        issuers = aiaSource.getCertificatesByAIA(certificate);
        assertEquals(1, issuers.size());
        assertEquals(1, dataLoader.counter);

        dataLoader = new MockCommonsDataLoader();
        aiaSource.setDataLoader(dataLoader);
        aiaSource.setAcceptedProtocols(Collections.singletonList(Protocol.LDAP));

        issuers = aiaSource.getCertificatesByAIA(certificate);
        assertEquals(0, issuers.size());
        assertEquals(2, dataLoader.counter);

        dataLoader = new MockCommonsDataLoader();
        aiaSource.setDataLoader(dataLoader);
        aiaSource.setAcceptedProtocols(Collections.emptyList());

        issuers = aiaSource.getCertificatesByAIA(certificate);
        assertEquals(0, issuers.size());
        assertEquals(0, dataLoader.counter);
    }

    private class MockCommonsDataLoader extends CommonsDataLoader {

        private int counter = 0;

        @Override
        public byte[] get(String urlString) throws DSSException {
            ++counter;
            if (urlString.contains("ldap")) {
                // skip quickly (unable to request)
                return DSSUtils.EMPTY_BYTE_ARRAY;
            }
            return super.get(urlString);
        }

    }

}
