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
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pki.business.PostConstructInitializr;
import eu.europa.esig.dss.pki.revocation.PkiDataLoader;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class OnlineOCSPSourceTest {

    private static CertificateToken certificateToken;
    private static CertificateToken rootToken;

    private static CertificateToken goodUser;
    private static CertificateToken goodUserOCSPWithReqCertId;
    private static CertificateToken goodCa;
    private static CertificateToken ed25519goodUser;
    private static CertificateToken ed25519goodCa;
    static PkiDataLoader dataLoader=new PkiDataLoader();



    @BeforeAll
    public static void init() {
        certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));

        PostConstructInitializr initializr = new PostConstructInitializr();

        initializr.init();


        goodUser = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/good-user.crt"));
        goodUserOCSPWithReqCertId = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/good-user-ocsp-certid-digest.crt"));
        goodCa = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/good-ca.crt"));

        ed25519goodUser = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/Ed25519-good-user.crt"));
        ed25519goodCa = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/Ed25519-good-ca.crt"));
    }

    @Test
    public void testOCSPWithoutNonce() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
         ocspSource.setDataLoader(dataLoader);
        OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testOCSP() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setDataLoader(dataLoader);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        System.out.println(ocspToken.toString());
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testWithCustomDataLoaderConstructor() {
//        OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
        OnlineOCSPSource ocspSource = new OnlineOCSPSource(dataLoader);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testWithSetDataLoader() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setDataLoader(dataLoader);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testOCSPEd25519() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        OCSPToken ocspToken = ocspSource.getRevocationToken(ed25519goodUser, ed25519goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.ED25519, ocspToken.getSignatureAlgorithm());
        assertEquals(SignatureValidity.VALID, ocspToken.getSignatureValidity());
    }

    @Test
    public void testOCSPWithNonce() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setNonceSource(new SecureRandomNonceSource());
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

        /* 1) Test default behavior of OnlineOCSPSource */

        OnlineOCSPSource ocspSource = new OnlineOCSPSource();

        OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        /* 2) Test OnlineOCSPSource with a custom FileCacheDataLoader (without online loader) */

        // create a FileCacheDataLoader
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setFileCacheDirectory(cacheFolder);
        fileCacheDataLoader.setCacheExpirationTime(5000);
        fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());

        assertTrue(cacheFolder.exists());

        // nothing in cache
        OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource(fileCacheDataLoader);
        Exception exception = assertThrows(DSSExternalResourceException.class, () -> onlineOCSPSource.getRevocationToken(certificateToken, rootToken));
        assertTrue(exception.getMessage().contains("Unable to retrieve OCSP response for certificate with Id "));

        /* 3) Test OnlineOCSPSource with a custom FileCacheDataLoader (with pkiDataloader) */

        fileCacheDataLoader.setDataLoader(dataLoader);
        ocspSource = new OnlineOCSPSource(fileCacheDataLoader);

        // load from online
        ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        /* 4) Test OnlineOCSPSource with a custom FileCacheDataLoader (loading from cache) */

        fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());

        // load from cache
        ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        /* 5) Test OnlineOCSPSource with setDataLoader(fileCacheDataLoader) method */

        // test setDataLoader(dataLoader)
        ocspSource = new OnlineOCSPSource();
        ocspSource.setDataLoader(fileCacheDataLoader);

        ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testInjectExternalUrls() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        List<String> alternativeOCSPUrls = new ArrayList<>();
        alternativeOCSPUrls.add("http://wrong.url.com");

        RevocationSource<OCSP> currentOCSPSource = new AlternateUrlsSourceAdapter<>(ocspSource,
                alternativeOCSPUrls);
        OCSPToken ocspToken = (OCSPToken) currentOCSPSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
    }

    @Test
    public void customCertIDDigestAlgorithmTest() {
        OCSPDataLoader dataLoader = new OCSPDataLoader();
        dataLoader.setTimeoutConnection(10000);
        dataLoader.setTimeoutSocket(10000);

        OnlineOCSPSource ocspSource = new OnlineOCSPSource(dataLoader);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertNotNull(ocspToken);
        assertEquals(SignatureAlgorithm.RSA_SHA1, ocspToken.getSignatureAlgorithm()); // default value

        ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA256);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA256, ocspToken.getSignatureAlgorithm());

        ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA512);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());

        ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA3_256);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA3_256, ocspToken.getSignatureAlgorithm());

        ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA3_512);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA3_512, ocspToken.getSignatureAlgorithm());
    }

    @Test
    public void testNullDataLoader() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setDataLoader(null);

        Exception exception = assertThrows(NullPointerException.class,
                () -> ocspSource.getRevocationToken(certificateToken, rootToken));
        assertEquals("DataLoader is not provided !", exception.getMessage());
    }

}
