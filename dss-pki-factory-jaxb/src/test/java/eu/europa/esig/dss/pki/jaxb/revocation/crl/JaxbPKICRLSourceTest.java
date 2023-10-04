package eu.europa.esig.dss.pki.jaxb.revocation.crl;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JaxbPKICRLSourceTest extends AbstractTestJaxbPKI {

    private static CertificateToken goodUser;
    private static CertificateToken goodCa;
    private static CertificateToken rootCa;

    private static CertificateToken ed25519goodUser;
    private static CertificateToken ed25519goodCa;
    private static CertificateToken ed25519RootCa;
    private static CertificateToken revokedCa;
    private static CertificateToken sha3GoodCa;
    private static CertificateToken sha3RootCa;

    @BeforeAll
    public static void init() {
        goodUser = repository.getCertEntityBySubject("good-user").getCertificateToken();
        goodCa = repository.getCertEntityBySubject("good-ca").getCertificateToken();
        rootCa = repository.getCertEntityBySubject("root-ca").getCertificateToken();
        revokedCa = repository.getCertEntityBySubject("revoked-ca").getCertificateToken();
        sha3GoodCa = repository.getCertEntityBySubject("sha3-good-ca").getCertificateToken();
        sha3RootCa = repository.getCertEntityBySubject("sha3-root-ca").getCertificateToken();

        ed25519goodUser = repository.getCertEntityBySubject("Ed25519-good-user").getCertificateToken();
        ed25519goodCa = repository.getCertEntityBySubject("Ed25519-good-ca").getCertificateToken();
        ed25519RootCa = repository.getCertEntityBySubject("Ed25519-root-ca").getCertificateToken();
    }

    @Test
    public void getRevocationTokenTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(rootCa, revocationToken.getIssuerCertificateToken());
        assertEquals(SignatureAlgorithm.RSA_SHA256, revocationToken.getSignatureAlgorithm());
        assertEquals(CertificateStatus.GOOD, revocationToken.getStatus());
    }

    @Test
    public void getRevocationTokenWithCertEntityTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource(repository.getByCertificateToken(rootCa));
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(rootCa, revocationToken.getIssuerCertificateToken());
    }

    @Test
    public void setCRLIssuerTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setCRLIssuer(repository.getByCertificateToken(rootCa));
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(rootCa, revocationToken.getIssuerCertificateToken());
    }

    @Test
    public void getRevokedTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(revokedCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(CertificateStatus.REVOKED, revocationToken.getStatus());
    }

    @Test
    public void getRevocationTokenSha3() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(sha3GoodCa, sha3RootCa);
        assertNotNull(revocationToken);
        assertEquals(SignatureAlgorithm.RSA_SHA3_256, revocationToken.getSignatureAlgorithm());
    }

    @Test
    public void getRevocationTokenWithMaskGenerationFunction() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, revocationToken.getSignatureAlgorithm());
    }

    @Test
    public void getRevocationTokenEd25519Test() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        CRLToken revocationToken = pkiCRLSource.getRevocationToken(ed25519goodUser, ed25519goodCa);

        assertNull(revocationToken);

        pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        revocationToken = pkiCRLSource.getRevocationToken(ed25519goodCa, ed25519RootCa);
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        assertNotNull(revocationToken);
        assertTrue(revocationToken.isSignatureIntact());
        assertTrue(revocationToken.isValid());
        assertEquals(SignatureAlgorithm.ED25519, revocationToken.getSignatureAlgorithm());
        assertEquals(SignatureValidity.VALID, revocationToken.getSignatureValidity());
    }

    @Test
    public void getRevocationThisUpdateTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();

        Date thisUpdate = DSSUtils.getUtcDate(2023, 6, 6);
        pkiCRLSource.setThisUpdate(thisUpdate);

        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(thisUpdate, revocationToken.getThisUpdate());
    }

    @Test
    public void getRevocationNextUpdateTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();

        Date nextUpdate = DSSUtils.getUtcDate(2023, 6, 6);
        pkiCRLSource.setNextUpdate(nextUpdate);

        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(nextUpdate, revocationToken.getNextUpdate());
    }

    @Test
    public void setNullRepositoryTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new PKICRLSource(null));
        assertEquals("Certificate repository shall be provided!", exception.getMessage());
    }

    @Test
    public void setNullCertificateTokenTest() {
        PKICRLSource crlSource = new PKICRLSource(repository);
        Exception exception = assertThrows(NullPointerException.class, () -> crlSource.getRevocationToken(null, goodCa));
        assertEquals("Certificate cannot be null!", exception.getMessage());
    }

    @Test
    public void setNullIssuerCertificateTokenTest() {
        PKICRLSource crlSource = new PKICRLSource(repository);
        Exception exception = assertThrows(NullPointerException.class, () -> crlSource.getRevocationToken(goodUser, null));
        assertEquals("The issuer of the certificate to be verified cannot be null!", exception.getMessage());
    }

    private static PKICRLSource initPkiCRLSource() {
        return initPkiCRLSource(null);
    }

    private static PKICRLSource initPkiCRLSource(CertEntity crlIssuer) {
        PKICRLSource pkiCRLSource = crlIssuer != null ? new PKICRLSource(repository, crlIssuer) : new PKICRLSource(repository);

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 6);
        Date nextUpdate = cal.getTime();
        pkiCRLSource.setNextUpdate(nextUpdate);
        pkiCRLSource.setThisUpdate(new Date());
        return pkiCRLSource;
    }

}
