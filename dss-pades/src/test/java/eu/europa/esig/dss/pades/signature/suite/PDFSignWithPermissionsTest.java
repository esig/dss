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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PDFSignWithPermissionsTest extends AbstractPAdESTestSignature {

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    void test() {
        // /DocMDP /P=1
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/certified-no-change-permitted.pdf"));
        Exception exception = assertThrows(ProtectedDocumentException.class, () -> sign());
        assertEquals("The creation of new signatures is not permitted in the current document. " +
                "Reason : DocMDP dictionary does not permit a new signature creation!", exception.getMessage());

        // /DocMDP /P=2
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1188/Test.pdf"));
        DSSDocument signedDoc = sign();
        assertNotNull(signedDoc);

        // /DocMDP /P=3
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/certified-changes-permitted.pdf"));
        signedDoc = sign();
        assertNotNull(signedDoc);

        // /FieldMDP /All
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
        exception = assertThrows(ProtectedDocumentException.class, () -> sign());
        assertEquals("The creation of new signatures is not permitted in the current document. " +
                "Reason : FieldMDP dictionary does not permit a new signature creation!", exception.getMessage());

        // /FieldMDP /Include
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/fieldmdp-include.pdf"));
        signedDoc = sign();
        assertNotNull(signedDoc);

        // FieldMDP /Exclude
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/fieldmdp-exclude.pdf"));
        signedDoc = sign();
        assertNotNull(signedDoc);

        // FieldMDP /Exclude signed (no permission defined)
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/fieldmdp-exclude-signed.pdf"));
        signedDoc = sign();
        assertNotNull(signedDoc);

        List<String> availableSignatureFields = service.getAvailableSignatureFields(documentToSign);
        assertEquals(2, availableSignatureFields.size());

        signatureParameters.getImageParameters().getFieldParameters().setFieldId(availableSignatureFields.get(0));
        signedDoc = sign();
        assertNotNull(signedDoc);
    }

    @Override
    public void signAndVerify() {
        // skip
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
