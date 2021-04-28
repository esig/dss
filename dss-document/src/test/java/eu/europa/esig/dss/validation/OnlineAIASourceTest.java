package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.AIASource;
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
        certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/certificates/TSP_Certificate_2014.crt"));
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
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/citizen_ca.cer"));
        OnlineAIASource aiaSource = new OnlineAIASource();
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificate);
        assertTrue(Utils.isCollectionEmpty(issuers));
        assertTrue(certificate.isCA());
    }

}
