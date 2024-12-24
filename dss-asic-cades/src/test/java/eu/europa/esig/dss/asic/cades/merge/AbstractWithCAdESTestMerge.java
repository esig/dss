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
package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.common.merge.AbstractASiCTestMerge;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractWithCAdESTestMerge extends
        AbstractASiCTestMerge<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> {

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertEquals(getExpectedASiCContainerType(), diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    protected abstract ASiCContainerType getExpectedASiCContainerType();

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNotNull(signatureWrapper.getSignatureValue());
        }
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();

        if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
            for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
                SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

                SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
                assertNotNull(signatureIdentifier);

                assertNotNull(signatureIdentifier.getSignatureValue());
                assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
            }
        }
    }

    @Override
    protected void checkMimeType(DiagnosticData diagnosticData) {
        super.checkMimeType(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (!signatureWrapper.isCounterSignature() && Utils.isStringEmpty(signatureWrapper.getContentHints())) {
                assertNotNull(signatureWrapper.getMimeType());
            } else {
                assertNull(signatureWrapper.getMimeType());
            }
        }
    }

}
