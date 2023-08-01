package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EntityStoreTSPSourceTest {

    private static final File KS_FILE = new File("src/test/resources/self-signed-tsa.p12");
    private static final String KS_TYPE = "PKCS12";
    private static final char[] KS_PASSWORD = "ks-password".toCharArray();
    private static final String ALIAS = "self-signed-tsa";

    private static final byte[] DTBS = "Hello World!".getBytes();

    @Test
    public void test() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        assertTimestampValid(timeStampResponse, digest);
    }

    @Test
    public void initEmptyTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource();

        KeyStore keyStore = KeyStore.getInstance(KS_TYPE);
        keyStore.load(Files.newInputStream(KS_FILE.toPath()), KS_PASSWORD);
        tspSource.setKeyStore(keyStore);

        tspSource.setAlias(ALIAS);
        tspSource.setKeyEntryPassword(KS_PASSWORD);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        assertTimestampValid(timeStampResponse, digest);
    }

    @Test
    public void acceptedDigestAlgorithmsTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, DTBS);
        Exception exception = assertThrows(DSSException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
        assertEquals("DigestAlgorithm 'SHA1' is not supported by the KeyStoreTSPSource implementation!", exception.getMessage());

        tspSource.setAcceptedDigestAlgorithms(Collections.singletonList(DigestAlgorithm.SHA1));
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
        assertTimestampValid(timeStampResponse, digest);
    }

    @Test
    public void tsaPolicyTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy("1.5.6.7.8.9");

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals("1.5.6.7.8.9", timeStampToken.getTimeStampInfo().getPolicy().getId());
    }

    @Test
    public void productionDateTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);

        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(2022, Calendar.JANUARY, 1);
        Date time = calendar.getTime();
        tspSource.setProductionTime(time);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(0, time.compareTo(timeStampToken.getTimeStampInfo().getGenTime()));
    }

    @Test
    public void serialNumberTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponseOne = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampTokenOne = assertTimestampValid(timeStampResponseOne, digest);
        TimestampBinary timeStampResponseTwo = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampTokenTwo = assertTimestampValid(timeStampResponseTwo, digest);
        assertNotEquals(timeStampTokenOne.getTimeStampInfo().getSerialNumber(), timeStampTokenTwo.getTimeStampInfo().getSerialNumber());
    }

    @Test
    public void digestAlgoTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(SignatureAlgorithm.RSA_SHA256.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());

        tspSource.setTstDigestAlgorithm(DigestAlgorithm.SHA512);

        timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(SignatureAlgorithm.RSA_SHA512.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());
    }

    @Test
    public void pssTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(SignatureAlgorithm.RSA_SHA256.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());

        tspSource.setEnablePSS(true);

        timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        timeStampToken = assertTimestampValid(timeStampResponse, digest);
        // the same OID is used for RSAwithANYandMGF1
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());
    }

    @Test
    public void errorTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource();

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        Exception exception = assertThrows(NullPointerException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest));
        assertEquals("KeyStore is not defined!", exception.getMessage());

        KeyStore keyStore = KeyStore.getInstance(KS_TYPE);
        try (InputStream is = Files.newInputStream(KS_FILE.toPath())) {
            keyStore.load(is, KS_PASSWORD);
        }

        tspSource.setKeyStore(keyStore);
        exception = assertThrows(NullPointerException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest));
        assertEquals("Alias is not defined!", exception.getMessage());

        tspSource.setAlias(ALIAS);
        exception = assertThrows(NullPointerException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest));
        assertEquals("Password from key entry is not defined!", exception.getMessage());

        tspSource.setKeyEntryPassword(KS_PASSWORD);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        assertTimestampValid(timeStampResponse, digest);

        tspSource.setAlias("wrong-alias");
        exception = assertThrows(IllegalArgumentException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest));
        assertEquals("No related/supported key entry found for alias 'wrong-alias'!", exception.getMessage());

        tspSource.setAlias(ALIAS);
        tspSource.setKeyEntryPassword("wrong-password".toCharArray());
        exception = assertThrows(DSSException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest));
        assertTrue(exception.getMessage().contains("Unable to recover the key entry with alias 'self-signed-tsa'."));
    }

    private TimeStampToken assertTimestampValid(TimestampBinary timestampBinary, byte[] digest) throws Exception {
        assertNotNull(timestampBinary);
        assertNotNull(timestampBinary.getBytes());
        assertFalse(Arrays.equals(new byte[] {}, timestampBinary.getBytes()));

        CMSSignedData cmsSignedData = new CMSSignedData(timestampBinary.getBytes());
        TimeStampToken timeStampToken = new TimeStampToken(cmsSignedData);
        assertArrayEquals(digest, timeStampToken.getTimeStampInfo().getMessageImprintDigest());
        return timeStampToken;
    }
    
}
