package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.junit.jupiter.api.Test;

import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtensionTToLTOldRevocationTest extends XAdESExtensionTToLTTest {

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, -1);
        return getKeyStoreTSPSourceByNameAndTime(GOOD_TSA, calendar.getTime());
    }

    @Override
    protected PKICRLSource pkiCRLSource() {
        PKICRLSource crlSource = super.pkiCRLSource();

        Calendar calendar = Calendar.getInstance();
        calendar.set(2024, Calendar.JANUARY, 1);
        crlSource.setThisUpdate(calendar.getTime());

        calendar.set(2024, Calendar.JANUARY, 15);
        crlSource.setNextUpdate(calendar.getTime());

        return crlSource;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        certificateVerifier.setRevocationFallback(true);
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
        return certificateVerifier;
    }

    @Test
    @Override
    public void extendAndVerify() throws Exception {
        Exception exception = assertThrows(AlertException.class, super::extendAndVerify);
        assertTrue(exception.getMessage().contains("Fresh revocation data is missing for one or more certificate(s)."));
        assertTrue(exception.getMessage().contains("No revocation data found after the best signature time"));
        assertFalse(exception.getMessage().contains("NextUpdate"));
    }

}
