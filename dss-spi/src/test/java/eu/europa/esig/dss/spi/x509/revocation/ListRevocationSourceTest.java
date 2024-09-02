package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ListRevocationSourceTest {

    private static final CertificateToken CERT = DSSUtils.loadCertificate(new File("src/test/resources/sk_user.cer"));

    private static final CertificateToken CA_CERT = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));

    private static final DSSDocument OCSP_DOCUMENT = new FileDocument("src/test/resources/sk_ocsp.bin");

    private static final DSSDocument WRONG_OCSP_DOCUMENT = new FileDocument("src/test/resources/peru_ocsp.bin");

    @Test
    void multipleRevocationSourcesTest() {
        ListRevocationSource<OCSP> lrs = new ListRevocationSource<>();
        assertEquals(0, lrs.getNumberOfSources());
        assertEquals(0, lrs.getAllRevocationBinaries().size());
        assertEquals(0, lrs.getRevocationTokens(CERT, CA_CERT).size());

        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(OCSP_DOCUMENT);
        assertTrue(lrs.add(ocspSource));

        assertEquals(1, lrs.getNumberOfSources());
        assertEquals(1, lrs.getAllRevocationBinaries().size());
        assertEquals(1, lrs.getRevocationTokens(CERT, CA_CERT).size());

        ExternalResourcesOCSPSource ocspSourceTwo = new ExternalResourcesOCSPSource(OCSP_DOCUMENT);
        assertTrue(lrs.add(ocspSourceTwo));

        assertEquals(2, lrs.getNumberOfSources());
        assertEquals(1, lrs.getAllRevocationBinaries().size());
        assertEquals(1, lrs.getRevocationTokens(CERT, CA_CERT).size());

        ExternalResourcesOCSPSource ocspSourceThree = new ExternalResourcesOCSPSource(WRONG_OCSP_DOCUMENT);
        assertTrue(lrs.add(ocspSourceThree));

        assertEquals(3, lrs.getNumberOfSources());
        assertEquals(2, lrs.getAllRevocationBinaries().size());
        assertEquals(1, lrs.getRevocationTokens(CERT, CA_CERT).size());

        assertFalse(lrs.add(ocspSource));
        assertFalse(lrs.add(ocspSourceTwo));
        assertFalse(lrs.add(ocspSourceThree));
        assertEquals(3, lrs.getNumberOfSources());
    }

}
