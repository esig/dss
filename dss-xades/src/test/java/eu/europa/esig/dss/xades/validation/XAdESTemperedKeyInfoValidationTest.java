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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESTemperedKeyInfoValidationTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/xades-tampered-keyinfo.xml"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSignatureIntact());
        assertFalse(signature.isSignatureValid());
        assertFalse(diagnosticData.isBLevelTechnicallyValid(signature.getId()));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSigningCertificateIdentified());
        assertTrue(signature.isSigningCertificateReferencePresent());
        assertTrue(signature.isSigningCertificateReferenceUnique());

        CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
        assertNotNull(signingCertificateReference);
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // not parsed signing-certificate
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanCertificateObjects()));
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanCertificateReferences()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanRevocationObjects()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isStructuralValidationValid());
        assertTrue(signature.getStructuralValidationMessages().stream().anyMatch(m -> m.contains("ds:X509Certificate"))); // not valid base64
    }

    protected void validateSignerInformation(SignerInformationType signerInformation) {
        assertNull(signerInformation);
    }

}
