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
package eu.europa.esig.dss.cbades.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class COSEX509URLCertificateSourceTest {

    private static final String URL = "https://nowina.lu/pki-factory/good-pki/cert-chain";

    private static CertificateToken token;
    private static CertificateToken token2;

    @BeforeAll
    static void init() {
        token = DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer"));
        token2 = DSSUtils.loadCertificate(new File("src/test/resources/CZ_CA.cer"));
    }

    @Test
    void test() {
        HashMap<String, byte[]> map = new HashMap<>();
        map.put(URL, token.getEncoded());

        MemoryDataLoader dataLoader = new MemoryDataLoader(map);

        COSEX509URLCertificateSource x509URLCertificateSource = new COSEX509URLCertificateSource(dataLoader);
        assertEquals(Collections.singletonList(token), x509URLCertificateSource.getCertificatesByUrl(URL));

        map.put(URL, DSSUtils.convertToPEM(token).getBytes());
        dataLoader = new MemoryDataLoader(map);

        x509URLCertificateSource = new COSEX509URLCertificateSource(dataLoader);
        assertEquals(Collections.singletonList(token), x509URLCertificateSource.getCertificatesByUrl(URL));

        CBORValue cborByteString = CBOR.bytes(token.getEncoded());
        map.put(URL, CBORUtils.serializeCbor(cborByteString));
        dataLoader = new MemoryDataLoader(map);

        x509URLCertificateSource = new COSEX509URLCertificateSource(dataLoader);
        assertEquals(Collections.singletonList(token), x509URLCertificateSource.getCertificatesByUrl(URL));

        CBORValue cborValue = CBOR.array()
                .add(CBOR.bytes(token.getEncoded()))
                .add(CBOR.bytes(token2.getEncoded()))
                .value();
        map.put(URL, CBORUtils.serializeCbor(cborValue));
        dataLoader = new MemoryDataLoader(map);

        x509URLCertificateSource = new COSEX509URLCertificateSource(dataLoader);
        assertEquals(Arrays.asList(token, token2), x509URLCertificateSource.getCertificatesByUrl(URL));

        cborValue = CBOR.map()
                .put(URL, CBOR.bytes(token.getEncoded()))
                .value();
        map.put(URL, CBORUtils.serializeCbor(cborValue));
        dataLoader = new MemoryDataLoader(map);

        x509URLCertificateSource = new COSEX509URLCertificateSource(dataLoader);
        assertEquals(Collections.emptyList(), x509URLCertificateSource.getCertificatesByUrl(URL));

        map.put(URL, DSSUtils.EMPTY_BYTE_ARRAY);
        dataLoader = new MemoryDataLoader(map);

        x509URLCertificateSource = new COSEX509URLCertificateSource(dataLoader);
        assertEquals(Collections.emptyList(), x509URLCertificateSource.getCertificatesByUrl(URL));
    }

}
