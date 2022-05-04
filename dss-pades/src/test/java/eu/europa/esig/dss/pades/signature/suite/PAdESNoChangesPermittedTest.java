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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.AbstractPdfObjFactory;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESNoChangesPermittedTest extends AbstractPAdESTestSignature {

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(
                getClass().getResourceAsStream("/validation/dss-2554/certified-no-change-permitted.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        PAdESNoChangesPermittedTest.MockLogAlertPdfObjectFactory pdfObjectFactory = new PAdESNoChangesPermittedTest.MockLogAlertPdfObjectFactory();
        pdfObjectFactory.setAlertOnForbiddenSignatureCreation(new ExceptionOnStatusAlert());
        service.setPdfObjFactory(pdfObjectFactory);

        Exception exception = assertThrows(AlertException.class, () -> super.sign());
        assertTrue(exception.getMessage().contains("The creation of new signatures is not permitted in the current document."));

        pdfObjectFactory.setAlertOnForbiddenSignatureCreation(new LogOnStatusAlert());
        return super.sign();
    }

    @Test
    @Override
    public void signAndVerify() {
        final DSSDocument signedDocument = sign();
        SignedDocumentValidator validator = getValidator(signedDocument);
        assertEquals(2, validator.getSignatures().size());
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

    private static class MockLogAlertPdfObjectFactory extends AbstractPdfObjFactory {

        private static final IPdfObjFactory pdfObjectFactory = new ServiceLoaderPdfObjFactory();

        private static AbstractPDFSignatureService service;

        static {
            service = (AbstractPDFSignatureService) pdfObjectFactory.newPAdESSignatureService();
        }

        public void setAlertOnForbiddenSignatureCreation(StatusAlert alertOnSignatureFieldOutsidePageDimensions) {
            service.setAlertOnForbiddenSignatureCreation(alertOnSignatureFieldOutsidePageDimensions);
        }

        @Override
        public PDFSignatureService newPAdESSignatureService() {
            return service;
        }

        @Override
        public PDFSignatureService newContentTimestampService() {
            return service;
        }

        @Override
        public PDFSignatureService newSignatureTimestampService() {
            return service;
        }

        @Override
        public PDFSignatureService newArchiveTimestampService() {
            return service;
        }

    }

}
