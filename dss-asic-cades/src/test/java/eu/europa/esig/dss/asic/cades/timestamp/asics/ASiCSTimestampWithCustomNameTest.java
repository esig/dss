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
package eu.europa.esig.dss.asic.cades.timestamp.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSTimestampWithCustomNameTest extends PKIFactoryAccess {

    @Test
    public void test() throws IOException {
        ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        filenameFactory.setTimestampFilename("timestamp1.tst");
        service.setAsicFilenameFactory(filenameFactory);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> service.timestamp(documentToSign, timestampParameters));
        assertEquals("A timestamp file within ASiC-S with CAdES container shall have name " +
                "'META-INF/timestamp.tst'!", exception.getMessage());

        filenameFactory.setTimestampFilename("timestamp.tst");

        DSSDocument archiveWithTimestamp = service.timestamp(documentToSign, timestampParameters);
        assertNotNull(archiveWithTimestamp);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(archiveWithTimestamp);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports = validator.validateDocument();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(0, diagnosticData.getSignatureIdList().size());
        assertEquals(1, diagnosticData.getTimestampIdList().size());

        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isSignatureValid());
            assertEquals("META-INF/timestamp.tst", timestamp.getFilename());
        }

        exception = assertThrows(IllegalInputException.class, () -> service.timestamp(archiveWithTimestamp, timestampParameters));
        assertEquals("The filename 'META-INF/timestamp.tst' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());

        filenameFactory.setTimestampFilename("timestamp1.tst");

        DSSDocument doubleTimestampedArchive = service.timestamp(archiveWithTimestamp, timestampParameters);

        validator = SignedDocumentValidator.fromDocument(doubleTimestampedArchive);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        reports = validator.validateDocument();
        assertNotNull(reports);

        diagnosticData = reports.getDiagnosticData();
        assertEquals(0, diagnosticData.getSignatureIdList().size());
        assertEquals(2, diagnosticData.getTimestampIdList().size());

        boolean firstTimestampFound = false;
        boolean secondTimestampFound = false;
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isSignatureValid());
            if ("META-INF/timestamp.tst".equals(timestamp.getFilename())) {
                firstTimestampFound = true;
            } else if ("META-INF/timestamp1.tst".equals(timestamp.getFilename())) {
                secondTimestampFound = true;
            }
        }
        assertTrue(firstTimestampFound);
        assertTrue(secondTimestampFound);
    }

    @Override
    protected String getSigningAlias() {
        return null;
    }

}
