/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pki.business.PostConstructInitializr;
import eu.europa.esig.dss.pki.db.Db;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.revocation.crl.PkiCRLSource;
import eu.europa.esig.dss.pki.revocation.ocsp.PkiOCSPSource;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class PkiOCSPSourceTest {

    private static CertificateToken certificateToken;
    private static CertificateToken rootToken;

    private static CertificateToken goodUser;
    private static CertificateToken goodUserOCSPWithReqCertId;
    private static CertificateToken goodCa;
    private static CertificateToken ed25519goodUser;
    private static CertificateToken ed25519goodCa;
    static OCSPDataLoader dataLoader = new OCSPDataLoader();
    static CertEntityRepository certificateEntityService = Db.getInstance();
    private static CertEntity certEntity;

    @BeforeAll
    public static void init() {
        PostConstructInitializr initializr = new PostConstructInitializr();
        initializr.init();

        certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
//        certificateToken = certificateEntityService.getCertEntity("Test-National-RootCA-from-ZZ").getCertificateToken();
//        rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
        certEntity = certificateEntityService.getCertEntity("good-user");
        rootToken = certificateEntityService.getCertEntity("root-ca").getCertificateToken();



        goodUser = certEntity.getCertificateToken();
        goodUserOCSPWithReqCertId = certificateEntityService.getCertEntity("good-user-ocsp-certid-digest").getCertificateToken();
        goodCa = certEntity.getCertificateToken();
        ed25519goodUser = certificateEntityService.getCertEntity("Ed25519-good-user").getCertificateToken();
        ed25519goodCa = certificateEntityService.getCertEntity("Ed25519-good-ca").getCertificateToken();

    }

    @Test
    public void testOCSPWithoutNonce() {
        PkiOCSPSource ocspSource = new PkiOCSPSource(certificateEntityService, certEntity);
//        ocspSource.setDataLoader(dataLoader);
        OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testOCSP() {

        PkiOCSPSource ocspSource = new PkiOCSPSource(certificateEntityService, certEntity);
//        ocspSource.setDataLoader(dataLoader);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        System.out.println(ocspToken.toString());
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void getRevocationTokenTest() {
        CRLToken revocationToken = new OnlineCRLSource().getRevocationToken(goodUser, goodCa);
        assertNull(revocationToken);

        revocationToken = new OnlineCRLSource().getRevocationToken(goodCa, rootToken);
        assertNotNull(revocationToken);
    }

    @Test
    public void testWithCustomDataLoaderConstructor() {
//        OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
        CertEntity goodUser = Db.getInstance().getCertEntity("good-user");
        CertEntity goodCa = Db.getInstance().getCertEntity("good-ca");

        PkiCRLSource ocspSource = new PkiCRLSource(Db.getInstance());
        ocspSource.setProductionDate(new Date());

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 6);
        Date nextUpdate = cal.getTime();

        ocspSource.setNextUpdate(nextUpdate);
        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA256);
        ocspSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);
        CRLToken ocspToken = ocspSource.getRevocationToken(goodUser.getCertificateToken(), goodCa.getCertificateToken());
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getCrlValidity());
    }

    private static OnlineCRLSource onlineCRLSource = new OnlineCRLSource();

    @Test
    public void getRevocationTokenWithAlternateUrlTest() {
        CRLToken wrongRevocationToken = onlineCRLSource.getRevocationToken(goodUser, goodCa, new ArrayList<>());
        assertNull(wrongRevocationToken);

        CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodCa, DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/root-ca.crt")), new ArrayList<>());
        assertNotNull(revocationToken);
    }

    @Test
    public void testWithSetDataLoader() {
        PkiOCSPSource ocspSource = new PkiOCSPSource(certificateEntityService);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testOCSPEd25519() {
        PkiOCSPSource ocspSource = new PkiOCSPSource(certificateEntityService);
        ocspSource.setDigestAlgorithm(SignatureAlgorithm.ED25519.getDigestAlgorithm());
        OCSPToken ocspToken = ocspSource.getRevocationToken(ed25519goodUser, ed25519goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.ED25519, ocspToken.getSignatureAlgorithm());
        assertEquals(SignatureValidity.VALID, ocspToken.getSignatureValidity());
    }

    @Test
    public void testOCSPWithNonce() {
        PkiOCSPSource ocspSource = new PkiOCSPSource(certificateEntityService, certEntity);

        OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
    }

    @Test
    public void testOCSPWithFileCache() {
        File cacheFolder = new File("target/ocsp-cache");

        // clean cache if exists
        if (cacheFolder.exists()) {
            Arrays.asList(cacheFolder.listFiles()).forEach(File::delete);
        }

        /* 1) Test default behavior of PkiOCSPSource */

        PkiOCSPSource ocspSource = new PkiOCSPSource(certificateEntityService);
        ocspSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);
        OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        /* 2) Test PkiOCSPSource with a custom FileCacheDataLoader (without online loader) */

        // create a FileCacheDataLoader
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setFileCacheDirectory(cacheFolder);
        fileCacheDataLoader.setCacheExpirationTime(5000);
        fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());

        assertTrue(cacheFolder.exists());

        // nothing in cache
        PkiOCSPSource PkiOCSPSource = new PkiOCSPSource(certificateEntityService);
        Exception exception = assertThrows(DSSExternalResourceException.class, () -> PkiOCSPSource.getRevocationToken(certificateToken, rootToken));
        assertTrue(exception.getMessage().contains("Unable to retrieve OCSP response for certificate with Id "));

        /* 3) Test PkiOCSPSource with a custom FileCacheDataLoader (with pkiDataloader) */

        fileCacheDataLoader.setDataLoader(dataLoader);
        ocspSource = new PkiOCSPSource(certificateEntityService);

        // load from online
        ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        /* 4) Test PkiOCSPSource with a custom FileCacheDataLoader (loading from cache) */

        fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());

        // load from cache
        ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        /* 5) Test PkiOCSPSource with setDataLoader(fileCacheDataLoader) method */

        // test setDataLoader(dataLoader)
        ocspSource = new PkiOCSPSource(certificateEntityService);

        ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }


    @Test
    public void customCertIDDigestAlgorithmTest() {
        OCSPDataLoader dataLoader = new OCSPDataLoader();
        dataLoader.setTimeoutConnection(10000);
        dataLoader.setTimeoutSocket(10000);

        PkiOCSPSource ocspSource = new PkiOCSPSource(certificateEntityService);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertNotNull(ocspToken);
        assertEquals(SignatureAlgorithm.RSA_SHA1, ocspToken.getSignatureAlgorithm()); // default value

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA256);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA256, ocspToken.getSignatureAlgorithm());

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA512);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA3_256, ocspToken.getSignatureAlgorithm());

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA3_512);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA3_512, ocspToken.getSignatureAlgorithm());
    }


}
