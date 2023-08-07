import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.business.PostConstructInitializr;
import eu.europa.esig.dss.pki.db.Db;
import eu.europa.esig.dss.pki.factory.GenericFactory;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.revocation.crl.PkiCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class PkiCRLSourceTest {


    private static CertEntityRepository certEntityRepository = GenericFactory.getInstance().create(Db.class);

    private static CertificateToken goodUser;
    private static CertificateToken goodCa;
    private static CertificateToken rootCa;

    private static CertificateToken ed25519goodUser;
    private static CertificateToken ed25519goodCa;
    private static CertificateToken ed25519RootCa;
    private static CertificateToken revokedCa;
    private static CertificateToken revokedUser;
    private static CertEntity certEntity;
    private static PkiCRLSource pkiCRLSource;

    @BeforeAll
    public static void init() {
        PostConstructInitializr.getInstance();

        certEntity = certEntityRepository.getCertEntity("good-ca");


        goodUser = certEntityRepository.getCertEntity("good-user").getCertificateToken();
        goodCa = certEntity.getCertificateToken();
        rootCa = certEntityRepository.getCertEntity("root-ca").getCertificateToken();
        revokedCa = certEntityRepository.getCertEntity("revoked-ca").getCertificateToken();
        revokedUser = certEntityRepository.getCertEntity("revoked-user").getCertificateToken();


        ed25519goodUser = certEntityRepository.getCertEntity("Ed25519-good-user").getCertificateToken();
        ed25519goodCa = certEntityRepository.getCertEntity("Ed25519-good-ca").getCertificateToken();
        ed25519RootCa = certEntityRepository.getCertEntity("Ed25519-root-ca").getCertificateToken();

    }

    @Test
    public void getRevocationTokenTest() {
        pkiCRLSource = initPkiCRLSource();
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(revocationToken);

        pkiCRLSource = initPkiCRLSource();

        revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
    }

    @Test
    public void getRevocationTokenWithCertEntityTest() {
        pkiCRLSource = initPkiCRLSource(true);
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(revocationToken);

        pkiCRLSource = initPkiCRLSource();

        revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
    }
   @Test
    public void getRevocationToken() {
        pkiCRLSource = initPkiCRLSource(true);
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(revokedUser,goodCa );
        assertNotNull(revocationToken);

        pkiCRLSource = initPkiCRLSource();

        revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
    }

    @Test
    public void getRevocationTokenWithMaskGenerationFunction() {
        pkiCRLSource = initPkiCRLSource();
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(revocationToken);

        pkiCRLSource = initPkiCRLSource();

        pkiCRLSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

        revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
    }

    @Test
    public void getRevocationTokenEd25519Test() {
        pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        CRLToken revocationToken = pkiCRLSource.getRevocationToken(ed25519goodUser, ed25519goodCa);

        assertNotNull(revocationToken);

        pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        revocationToken = pkiCRLSource.getRevocationToken(ed25519goodCa, ed25519RootCa);
//        pkiCRLSource.setDigestAlgorithm(SignatureAlgorithm.ED25519.getDigestAlgorithm());

        assertNotNull(revocationToken);
        assertTrue(revocationToken.isSignatureIntact());
        assertTrue(revocationToken.isValid());
        assertEquals(SignatureAlgorithm.ED25519, revocationToken.getSignatureAlgorithm());
        assertEquals(SignatureValidity.VALID, revocationToken.getSignatureValidity());
    }


    public static PkiCRLSource initPkiCRLSource(boolean... useCertEntity) {

        PkiCRLSource pkiCRLSource = useCertEntity.length > 0 && useCertEntity[0] ? new PkiCRLSource(certEntityRepository, certEntity) : new PkiCRLSource(certEntityRepository);

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 6);
        Date nextUpdate = cal.getTime();
        pkiCRLSource.setNextUpdate(nextUpdate);
        pkiCRLSource.setProductionDate(new Date());
        return pkiCRLSource;

    }


}
