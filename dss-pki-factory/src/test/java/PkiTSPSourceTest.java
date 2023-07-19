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
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pki.business.PostConstructInitializr;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.revocation.PkiDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * How to initialize online TSP source.
 */

public class PkiTSPSourceTest {

    private static final Logger LOG = LoggerFactory.getLogger(PkiTSPSourceTest.class);

    @BeforeAll
    public static void contextLoads() {
        PostConstructInitializr initializr = new PostConstructInitializr();
        initializr.init();

    }

    @Test
    public void testError500() throws IOException {

        final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/error-500/good-tsa";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new PkiDataLoader()); // uses the specific content-type

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = "Hello world".getBytes("UTF-8");
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
        TimestampBinary tsBinary = null;

        Exception exception = assertThrows(Error500Exception.class, () -> tspSource.getTimeStampResponse(digestAlgorithm, digestValue));
        assertEquals("Something wrong happened", exception.getMessage());

    }

    @Test
    public void testBadUrl() throws IOException {

        final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/error-500/good-tsa/test/test";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new PkiDataLoader()); // uses the specific content-type

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = "Hello world".getBytes("UTF-8");
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);

        Exception exception = assertThrows(Error500Exception.class, () -> tspSource.getTimeStampResponse(digestAlgorithm, digestValue));
        assertEquals("Bad url", exception.getMessage());
        try {
            TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);
        } catch (Error500Exception error500Exception) {
            LOG.error(error500Exception.getMessage());
        }

    }


    @Test
    public void testSuccess() throws IOException {


        final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/good-tsa";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new PkiDataLoader()); // uses the specific content-type

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = "Hello world".getBytes("UTF-8");
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
        final TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

        LOG.info(DSSUtils.toHex(tsBinary.getBytes()));

        assertNotNull(tsBinary);
    }

    @Test
    public void testTimestampForDate() throws IOException {


        final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/2023-08-11-09-07/good-tsa";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new PkiDataLoader()); // uses the specific content-type

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = "Hello world".getBytes("UTF-8");
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
        final TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

        LOG.info(DSSUtils.toHex(tsBinary.getBytes()));

        assertNotNull(tsBinary);
    }


    @Test
    public void testFailTimestamp() throws IOException {


        final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/fail/good-tsa";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new PkiDataLoader()); // uses the specific content-type

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = "Hello world".getBytes("UTF-8");
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);

        Exception exception = assertThrows(DSSExternalResourceException.class, () -> tspSource.getTimeStampResponse(digestAlgorithm, digestValue));
        assertTrue(exception.getMessage().contains("Error for testing"));


    }

}
