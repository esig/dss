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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithXAdESEmptyOdtTest extends AbstractASiCWithXAdESTestValidation {

    private DSSDocument signedDocument;

    public static Collection<Object[]> data() {
        File folder = new File("src/test/resources/opendocument");
        Collection<File> listFiles = Utils.listFiles(folder,
                new String[] { "odt", "ods", "odp", "odg" }, true);
        Collection<Object[]> dataToRun = new ArrayList<>();
        for (File file : listFiles) {
            dataToRun.add(new Object[] { file });
        }
        return dataToRun;
    }

    @ParameterizedTest
    @MethodSource("data")
    public void bLevelTest(File file) {
        signedDocument = new FileDocument(file);
        super.validate();
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return signedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(0, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertTrue(Utils.isCollectionEmpty(signatures));
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        assertNotNull(signatureValidationStatus);
        assertNotNull(signatureValidationStatus.getMainIndication());
        assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
    }

    @Override
    public void validate() {
        // skip
    }

}
