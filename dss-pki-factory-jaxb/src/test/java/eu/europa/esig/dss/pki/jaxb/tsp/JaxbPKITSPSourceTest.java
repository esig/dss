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
package eu.europa.esig.dss.pki.jaxb.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.x509.tsp.PKITSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JaxbPKITSPSourceTest extends AbstractTestJaxbPKI {

    private static final String TSA_POLICY = "1.2.3.4";

    @Test
    public void testSuccess() {
        CertEntity certEntity = repository.getCertEntityBySubject("good-tsa");
        PKITSPSource tspSource = new PKITSPSource(certEntity);
        tspSource.setTsaPolicy(TSA_POLICY);

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = "Hello world".getBytes(StandardCharsets.UTF_8);
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
        final TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);
        assertNotNull(tsBinary);
    }

    @Test
    public void testTimestampUnsupportedDigestAlgo() {
        CertEntity certEntity = repository.getCertEntityBySubject("good-tsa");
        PKITSPSource tspSource = new PKITSPSource(certEntity);
        tspSource.setTsaPolicy(TSA_POLICY);

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
        final byte[] toDigest = "Hello world good tsa".getBytes(StandardCharsets.UTF_8);
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);

        Exception exception = assertThrows(DSSException.class, () -> tspSource.getTimeStampResponse(digestAlgorithm, digestValue));
        assertTrue(exception.getMessage().contains("DigestAlgorithm '" + digestAlgorithm + "' is not supported by the KeyEntityTSPSource implementation!"));

        tspSource.setAcceptedDigestAlgorithms(Collections.singleton(DigestAlgorithm.SHA1));
        final TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);
        assertNotNull(tsBinary);
    }

    @Test
    public void testTimestampSha3DigestAlgo() {
        CertEntity certEntity = repository.getCertEntityBySubject("good-tsa");
        PKITSPSource tspSource = new PKITSPSource(certEntity);
        tspSource.setTsaPolicy(TSA_POLICY);

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA3_256;
        final byte[] toDigest = "Hello world good tsa".getBytes(StandardCharsets.UTF_8);
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);

        Exception exception = assertThrows(DSSException.class, () -> tspSource.getTimeStampResponse(digestAlgorithm, digestValue));
        assertTrue(exception.getMessage().contains("DigestAlgorithm '" + digestAlgorithm + "' is not supported by the KeyEntityTSPSource implementation!"));
    }

}
