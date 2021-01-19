package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TokenIdentifierProviderTest {

    private static CertificateToken certificate;

    @BeforeAll
    public static void init() {
        certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer"));
    }

    @Test
    public void originalIdentifierProviderTest() {
        OriginalIdentifierProvider originalIdentifierProvider = new OriginalIdentifierProvider();
        assertEquals(certificate.getDSSIdAsString(), originalIdentifierProvider.getIdAsString(certificate));
    }

    @Test
    public void userFriendlyIdentifierProviderTest() {
        UserFriendlyIdentifierProvider userFriendlyIdentifierProvider = new UserFriendlyIdentifierProvider();
        String id = userFriendlyIdentifierProvider.getIdAsStringForToken(certificate);
        assertTrue(id.contains("CERTIFICATE"));
        assertTrue(id.contains(DSSUtils.replaceAllNonAlphanumericCharacters(DSSASN1Utils.getSubjectCommonName(certificate), "-")));
        assertTrue(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));

        userFriendlyIdentifierProvider.setCertificatePrefix("CERT");
        id = userFriendlyIdentifierProvider.getIdAsStringForToken(certificate);
        assertTrue(id.contains("CERT"));
        assertFalse(id.contains("CERTIFICATE"));
        assertTrue(id.contains(DSSUtils.replaceAllNonAlphanumericCharacters(DSSASN1Utils.getSubjectCommonName(certificate), "-")));
        assertTrue(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));

        userFriendlyIdentifierProvider.setDateFormat("yyyy-MM-dd");
        id = userFriendlyIdentifierProvider.getIdAsStringForToken(certificate);
        assertTrue(id.contains("CERT"));
        assertTrue(id.contains(DSSUtils.replaceAllNonAlphanumericCharacters(DSSASN1Utils.getSubjectCommonName(certificate), "-")));
        assertTrue(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyy-MM-dd")));
        assertFalse(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));
    }

}
