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
package eu.europa.esig.dss.pades.timestamp.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBTest;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESTimestampWithAppNameTest extends AbstractPkiFactoryTestValidation {

    private static final String DSS_APP_NAME = "DSS";

    @Test
    void test() throws Exception {
        DSSDocument documentToTimestamp = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/sample.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setAppName(DSS_APP_NAME);

        DSSDocument timestampedDoc = service.timestamp(documentToTimestamp, timestampParameters);
        assertNotNull(timestampedDoc);

        String pathString = "target/timestamped.pdf";
        timestampedDoc.save(pathString);

        File file = new File(pathString);
        assertTrue(file.exists());

        checkAppNamePresence(timestampedDoc);
        verify(timestampedDoc);

        assertTrue(file.delete());
        assertFalse(file.exists());
    }

    private void checkAppNamePresence(DSSDocument document) {
        byte[] bytes = DSSUtils.toByteArray(document);
        String documentContent = new String(bytes);
        assertTrue(documentContent.contains("/" + PAdESConstants.PROP_BUILD));
        assertTrue(documentContent.contains("/" + PAdESConstants.APP));
        assertTrue(documentContent.contains("/" + DSS_APP_NAME));
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertFalse(Utils.isCollectionNotEmpty(signatures));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getSignatures()));
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);
        assertEquals(1, diagnosticData.getTimestampList().size());
    }

    @Override
    protected String getSigningAlias() {
        return null;
    }

}
