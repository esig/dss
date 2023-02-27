/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.x509.aia;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.AuthorityInformationAccess;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.aia.OnlineAIASource;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DefaultAIASourceTest {

    private static CertificateToken certificateWithAIA;

    @BeforeAll
    public static void init() {
        certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
        assertNotNull(certificateWithAIA);
    }

    @Test
    public void testLoadIssuer() {
        AIASource aiaSource = new DefaultAIASource();
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
        DefaultAIASource aiaSource = new DefaultAIASource();
        Exception exception = assertThrows(NullPointerException.class, () -> aiaSource.setDataLoader(null));
        assertEquals("dataLoader cannot be null!", exception.getMessage());
    }

    @Test
    public void emptyAcceptedProtocolsTest() {
        DefaultAIASource aiaSource = new DefaultAIASource();
        aiaSource.setAcceptedProtocols(Collections.emptySet());
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificateWithAIA);
        assertTrue(Utils.isCollectionEmpty(issuers));
    }

    @Test
    public void testLoadIssuerNoAIA() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.crt"));
        DefaultAIASource aiaSource = new DefaultAIASource();
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificate);
        assertTrue(Utils.isCollectionEmpty(issuers));
        assertTrue(certificate.isCA());
    }

    @Test
    public void acceptedProtocolsTest() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));
        MockCommonsDataLoader dataLoader = new MockCommonsDataLoader();

        DefaultAIASource aiaSource = new DefaultAIASource(dataLoader);

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

    @Test
    public void certificatesByAiaUrlTest() {
        CertificateToken certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));
        byte[] caCertStore = Utils.fromBase64("MIIIuAYJKoZIhvcNAQcCoIIIqTCCCKUCAQExADALBgkqhkiG9w0BBwGgggiNMIIIiTCCBnGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQGEwJTSzETMBEGA1UEBwwKQnJhdGlzbGF2YTEiMCAGA1UECgwZTmFyb2RueSBiZXpwZWNub3N0bnkgdXJhZDEOMAwGA1UECwwFU0lCRVAxFTATBgNVBAMMDEtDQSBOQlUgU1IgMzAeFw0wOTExMDYwOTU5MzlaFw0yNTExMDYwNzI5MDlaMG0xCzAJBgNVBAYTAlNLMRMwEQYDVQQHDApCcmF0aXNsYXZhMSIwIAYDVQQKDBlOYXJvZG55IGJlenBlY25vc3RueSB1cmFkMQ4wDAYDVQQLDAVTSUJFUDEVMBMGA1UEAwwMS0NBIE5CVSBTUiAzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA26rQjy9KlxLVuet9WdyDXIsxF/Llbl7OLNLFJ9xn6rOO8NcFIZfSlA1USbEfK+3kMJyNYJNyFi8OGQq3vv9/yRjJ5EARzVlns4ROhI/nxEahu4ET4VxVuyO5h0fmyJiGdFwJIPzFUxXYd2Z+u2OpLbNLynj4HG9k2CK6p5TB0CXzj4MUr7rbXF0sV+J3iQwcFSJol8C4gGln9wC4czC44jHWfZUSvQ3vK9hrSBbJJ3bYLZV/RawKvR4SkWDxnFiOti7ujULrWpfkgiCo2TDV4NSGsaGeXEIzoBShYRtppibHjmuLyFwZmvggY2/ux+EVwt6bgrlftQLpORF2rTQAdt10OyZNuMRphkKuDwgd1EhK4vW9XubLNbBCDBRhHG8dp7Vj/WOIVJPuQKR31O2ngnNiV4ItFLfVTU6h54/IgN4WDIM72Ak75yVInkqUbq1uYeHI375wIVUR1eLkW1FusT+wMYvVApZKg/0GX6lNLRmpQOOFv7iPXaoO4YSN761PkHJf5qJVyYS8dCM/ecpATRKR/RfdJSNmHcPHea8U+Zr5v+0f9DkWJ/zwzLAWNdU34C4s1LBmLA6uGAGfj8uesQ+5GRKCDcZwUA195XLN2o0JYner9ZY5L+DBTgjbxocxey55qvsEqWhiJO0KwkgwM//tHiO5WxS/RW6k1ts16OMCAwEAAaOCAzIwggMuMFAGA1UdIARJMEcwRQYNK4EekZmEBQAAAAECAjA0MDIGCCsGAQUFBwIBFiZodHRwOi8vZXAubmJ1c3Iuc2sva2NhL2RvYy9rY2FfY3BzLnBkZjAPBgNVHRMBAf8EBTADAQH/MIIBWAYDVR0fBIIBTzCCAUswMKAuoCyGKmh0dHA6Ly9lcC5uYnVzci5zay9rY2EvY3JsczMva2NhbmJ1c3IzLmNybDCBkKCBjaCBioaBh2xkYXA6Ly9lcC5uYnVzci5zay9jbiUzZEtDQSUyME5CVSUyMFNSJTIwMyxvdSUzZFNJQkVQLG8lM2ROYXJvZG55JTIwYmV6cGVjbm9zdG55JTIwdXJhZCxsJTNkQnJhdGlzbGF2YSxjJTNkU0s/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDCBg6CBgKB+hnxsZGFwOi8vL2NuJTNkS0NBJTIwTkJVJTIwU1IlMjAzLG91JTNkU0lCRVAsbyUzZE5hcm9kbnklMjBiZXpwZWNub3N0bnklMjB1cmFkLGwlM2RCcmF0aXNsYXZhLGMlM2RTSz9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MIIBPAYIKwYBBQUHAQsEggEuMIIBKjA7BggrBgEFBQcwBYYvaHR0cDovL2VwLm5idXNyLnNrL2tjYS9jZXJ0cy9rY2EzL2tjYW5idXNyMy5wN2MwegYIKwYBBQUHMAWGbmxkYXA6Ly9lcC5uYnVzci5zay9jbj1LQ0EgTkJVIFNSIDMsb3U9U0lCRVAsbz1OYXJvZG55IGJlenBlY25vc3RueSB1cmFkLGw9QnJhdGlzbGF2YSxjPVNLP2NhQ2VydGlmaWNhdGU7YmluYXJ5MG8GCCsGAQUFBzAFhmNsZGFwOi8vL2NuPUtDQSBOQlUgU1IgMyxvdT1TSUJFUCxvPU5hcm9kbnkgYmV6cGVjbm9zdG55IHVyYWQsbD1CcmF0aXNsYXZhLGM9U0s/Y2FDZXJ0aWZpY2F0ZTtiaW5hcnkwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR/8T0hwpdaLpcHDrFpgyX9IYY+BzANBgkqhkiG9w0BAQsFAAOCAgEANtv5EullQrKjuYnue9kecm9voLAnwqLqip4XEB22msgAuIrLkEteMt61k/BFgthXau9fBwD9CXu3qwTjtf+fyTgbU1aVR0b/ByzTbmkp179lQ5S8XOnawS9567JWNHaNiRW4XNN3WbQSsIfxBo5Vs1e0uW0GadTIXaRgMxwiWIpobd3nu1PbWlYPgi15dwRY4uSfjNQ1HFbVVgefi6Z4O32YKzxV38N+Os7uVsVcniyvI2Xo+MbUVzmdF2ExNvuguf06jekc/VfHSFY5zs1sMJyZI1aYmkbthQIHIQV5sK3/Bqv89I8Zx2CBwVTM/dgzzcdsNvh0RWkb3qK9tVqhJya2kGCFCD+h6Cya1d6TE4aWDub1dAX4L1w1lqdawG4rnz+HhoG5ZioUFzNdFJEYJCdCRcbrG0DsO25In1GZVbO6mhWcof6vwKW4cTknKi09MUe5l1q5oKu1VsIzDimymUe0B2sG5yWnkCYz91BaYQdabr11FlwiKriMNzlXcd4FC/o6MvPNPvUWzkiEV9wg82uztiKANqRaFYcO8sHYajx4IY1kELi9TUectuWL2EjaNp9OJnbL2YXCVemtb9PUYdZG+gWpH5DlEAxhsMpY+qH7x1sunu4NtwIZmdBKZG76MDwz0mCPgmYSous91QQBqeThl3hGnliUk8fF2aNJesAxAA==");

        Map<String, byte[]> dataMap = new HashMap<>();
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(certificateWithAIA);
        assertNotNull(aia);
        List<String> aiaUrls = aia.getCaIssuers();
        assertEquals(3, aiaUrls.size());
        for (String url : aiaUrls) {
            dataMap.put(url, caCertStore);
        }

        DefaultAIASource aiaSource = new DefaultAIASource(new MemoryDataLoader(dataMap));
        List<OnlineAIASource.CertificatesAndAIAUrl> certificatesAndAIAUrls = aiaSource.getCertificatesAndAIAUrls(certificateWithAIA);
        assertEquals(3, certificatesAndAIAUrls.size());
        for (OnlineAIASource.CertificatesAndAIAUrl certificatesByAiaUrl : certificatesAndAIAUrls) {
            assertNotNull(certificatesByAiaUrl.getAiaUrl());
            assertEquals(1, certificatesByAiaUrl.getCertificates().size());
        }
    }

    private static class MockCommonsDataLoader extends CommonsDataLoader {

        private static final long serialVersionUID = -7893617030310292695L;

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
