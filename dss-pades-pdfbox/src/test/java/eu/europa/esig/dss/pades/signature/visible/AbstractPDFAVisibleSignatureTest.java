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
package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PDFAUtils;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.test.UnmarshallingTester;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractPDFAVisibleSignatureTest extends PKIFactoryAccess {

    protected PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
	public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
        setCustomFactory();
    }

    /**
     * Set a custom instance of {@link IPdfObjFactory}
     */
    protected abstract void setCustomFactory();

    @Test
    public void testGeneratedTextOnly() throws IOException {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature");
        textParameters.setTextColor(Color.GREEN);
        imageParameters.setTextParameters(textParameters);
        signatureParameters.setImageParameters(imageParameters);

        signAndValidate(true);
    }

    @Test
    public void testGeneratedTextWithoutColor() throws IOException {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdf-without-outputintent.pdf"));
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setBackgroundColor(null);
        textParameters.setText("My signature");
        textParameters.setTextColor(null);
        imageParameters.setTextParameters(textParameters);
        signatureParameters.setImageParameters(imageParameters);

        signAndValidate(true);
    }

    @Test
    public void testGeneratedTextWithOnlyAlpha() throws IOException {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature");
        textParameters.setTextColor(new Color(0, 255, 0, 100));
        imageParameters.setTextParameters(textParameters);
        signatureParameters.setImageParameters(imageParameters);

        signAndValidate(false);
    }

    @Test
    public void testGeneratedImageOnly() throws IOException {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(100);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);

        signAndValidate(true);
    }

    @Test
    public void testGeneratedImageOnlyPNG() throws IOException {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        // PNG with ALPHA
        imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(100);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);

        Exception exception = assertThrows(AlertException.class, () -> signAndValidate(false));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		signAndValidate(false);
	}

	private void signAndValidate(boolean expectedValidPDFA) throws IOException {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

        assertEquals(expectedValidPDFA, PDFAUtils.validatePDFAStructure(signedDocument));

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

        UnmarshallingTester.unmarshallXmlReports(reports);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
