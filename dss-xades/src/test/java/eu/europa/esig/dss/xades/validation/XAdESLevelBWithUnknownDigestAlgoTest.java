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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectRepresentationType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class XAdESLevelBWithUnknownDigestAlgoTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-unknown-digest-algo.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new FileDocument("src/test/resources/sample.xml"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSignatureIntact());
        assertFalse(signature.isSignatureValid());
        assertFalse(signature.isBLevelTechnicallyValid());
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertEquals(1, Utils.collectionSize(signatureWrapper.getSignatureScopes()));
            XmlSignatureScope signatureScope = signatureWrapper.getSignatureScopes().get(0);
            assertNotNull(signatureScope.getScope());
            assertNotNull(signatureScope.getSignerData());
            assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue());
            assertNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
            assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
            assertArrayEquals(DSSUtils.EMPTY_BYTE_ARRAY, signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
        }
    }

    @Override
    protected void checkSignatureReports(Reports reports) {
        ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
            assertEquals(1, etsiValidationReportJaxb.getSignatureValidationReport().size());

        for (SignatureValidationReportType signatureValidationReport : etsiValidationReportJaxb.getSignatureValidationReport()) {
            assertNotNull(signatureValidationReport.getSignatureIdentifier());

            SignersDocumentType signersDocument = signatureValidationReport.getSignersDocument();
            List<ValidationObjectType> validationObjects = getValidationObjects(signersDocument);
            assertEquals(1, validationObjects.size());

            ValidationObjectType validationObject = validationObjects.get(0);

            ValidationObjectRepresentationType validationObjectRepresentation = validationObject.getValidationObjectRepresentation();
            assertNotNull(validationObjectRepresentation);
            DigestAlgAndValueType digestAlgAndValue = validationObjectRepresentation.getDigestAlgAndValue();
            assertNotNull(digestAlgAndValue);
            assertNotNull(digestAlgAndValue.getDigestMethod());
            assertEquals("?", digestAlgAndValue.getDigestMethod().getAlgorithm());
            assertNotNull(digestAlgAndValue.getDigestValue());
            assertArrayEquals(DSSUtils.EMPTY_BYTE_ARRAY, digestAlgAndValue.getDigestValue());
        }
    }

}
