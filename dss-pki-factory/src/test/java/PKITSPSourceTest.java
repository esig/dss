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
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pki.business.PostConstructInitializr;
import eu.europa.esig.dss.pki.db.Db;
import eu.europa.esig.dss.pki.factory.GenericFactory;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.revocation.tsp.PKITSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * How to initialize online TSP source.
 */

public class PKITSPSourceTest {

    private static final Logger LOG = LoggerFactory.getLogger(PKITSPSourceTest.class);
    CertEntityRepository certEntityRepository = GenericFactory.getInstance().create(Db.class);




    @Test
    public void testSuccess() {

        CertEntity certEntity = certEntityRepository.getCertEntity("good-tsa");
        PKITSPSource tspSource = new PKITSPSource(certEntity);

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = "Hello world".getBytes(StandardCharsets.UTF_8);
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
        final TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

        LOG.info(DSSUtils.toHex(tsBinary.getBytes()));

        assertNotNull(tsBinary);
    }

    @Test
    public void testTimestampFail() {


        CertEntity certEntity = certEntityRepository.getCertEntity("good-tsa");
        PKITSPSource tspSource = new PKITSPSource(certEntity);
        tspSource.setCertEntity(certEntity);

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA3_256;
        final byte[] toDigest = "Hello world good tsa".getBytes(StandardCharsets.UTF_8);
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);

        Exception exception = assertThrows(DSSException.class, () -> tspSource.getTimeStampResponse(digestAlgorithm, digestValue));
        assertTrue(exception.getMessage().contains("DigestAlgorithm '" + digestAlgorithm + "' is not supported by the PkiTSPSource implementation!"));
    }


}
