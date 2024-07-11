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
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.awt.Color;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESWithSignatureAndTimestampVisibleTest extends AbstractPAdESTestSignature {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		signatureImageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(25);
		fieldParameters.setOriginY(25);
		signatureImageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(signatureImageParameters);

		SignatureImageParameters timestampImageParameters = new SignatureImageParameters();
		
		SignatureFieldParameters tstFieldParameters = new SignatureFieldParameters();
		tstFieldParameters.setOriginX(100);
		tstFieldParameters.setOriginY(25);
		timestampImageParameters.setFieldParameters(tstFieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Timestamp");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
		timestampImageParameters.setTextParameters(textParameters);
		
		PAdESTimestampParameters archiveTimestampParameters = signatureParameters.getArchiveTimestampParameters();
		archiveTimestampParameters.setImageParameters(timestampImageParameters);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());

		SignatureWrapper signatureWrapper = signatures.get(0);
		assertTrue(signatureWrapper.arePdfObjectModificationsDetected());

		assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getPdfExtensionChanges()));
		assertFalse(Utils.isCollectionNotEmpty(signatureWrapper.getPdfSignatureOrFormFillChanges()));
		assertFalse(Utils.isCollectionNotEmpty(signatureWrapper.getPdfAnnotationChanges()));
		assertFalse(Utils.isCollectionNotEmpty(signatureWrapper.getPdfUndefinedChanges()));

		List<XmlObjectModification> secureChanges = signatureWrapper.getPdfExtensionChanges();
		assertEquals(3, secureChanges.size());

		boolean dssDictFound = false;
		boolean docTimeStampFound = false;
		boolean newFieldFound = false;

		assertTrue(secureChanges.stream().map(c -> c.getType()).collect(Collectors.toSet()).contains("DocTimeStamp"));
		for (XmlObjectModification objectModification : secureChanges) {
			assertEquals(PdfObjectModificationType.CREATION, objectModification.getAction());
			if (objectModification.getValue().contains("/DSS")) {
				dssDictFound = true;
			}
			if ("DocTimeStamp".equals(objectModification.getType())) {
				docTimeStampFound = true;
			}
			if ("Signature2".equals(objectModification.getFieldName())) {
				newFieldFound = true;
			}
		}
		assertTrue(dssDictFound);
		assertTrue(docTimeStampFound);
		assertTrue(newFieldFound);
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
