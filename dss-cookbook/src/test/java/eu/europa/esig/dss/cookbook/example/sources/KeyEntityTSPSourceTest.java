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
package eu.europa.esig.dss.cookbook.example.sources;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyEntityTSPSourceTest {

    @Test
    void test() throws Exception {
        String keyStoreFileName = "src/test/resources/self-signed-tsa.p12";
        char[] keyStorePassword = "ks-password".toCharArray();

        // tag::demo[]
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
        // import eu.europa.esig.dss.spi.x509.tsp.KeyStoreTSPSource;
        // import java.io.File;
        // import java.nio.file.Files;
        // import java.security.KeyStore;
        // import java.util.Arrays;
        // import java.util.Date;
        File keyStoreFile = new File(keyStoreFileName);

        // instantiate the KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(keyStoreFile.toPath()), keyStorePassword);

        // instantiate the KeyStoreTSPSource
       KeyEntityTSPSource entityStoreTSPSource = new KeyEntityTSPSource(keyStore, "self-signed-tsa", keyStorePassword);

        // This method allows definition of a timestamping policy
        // NOTE: The TSA Policy is mandatory to be provided!
        entityStoreTSPSource.setTsaPolicy("1.2.3.4");

        // This method allows configuration of digest algorithms to be supported for a timestamp request
        // Default: SHA-224, SHA-256, SHA-384, SHA-512
        entityStoreTSPSource.setAcceptedDigestAlgorithms(Arrays.asList(
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512));

        // This method allows definition of a custom production time of the timestamp
        // Default: the current time is used
        entityStoreTSPSource.setProductionTime(new Date());

        // This method allows definition of a digest algorithm to be used for a signature of the generated time-stamp
        // Default: SHA-512
        entityStoreTSPSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        // This method defines an Encryption algorithms to be used on signature creation
        // NOTE: the encryption algorithm shall be compatible with the used key on timestamp creation
        // Default: NONE (encryption algorithm returned by the key is used)
        entityStoreTSPSource.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);
        // end::demo[]

        DSSDocument documentToTimestamp = new InMemoryDocument("Hello World!".getBytes());
        byte[] messageImprint = DSSUtils.digest(DigestAlgorithm.SHA256, documentToTimestamp);
        TimestampBinary timeStampResponse = entityStoreTSPSource.getTimeStampResponse(DigestAlgorithm.SHA256, messageImprint);

        TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
        assertTrue(timestampToken.matchData(documentToTimestamp));
    }

}
