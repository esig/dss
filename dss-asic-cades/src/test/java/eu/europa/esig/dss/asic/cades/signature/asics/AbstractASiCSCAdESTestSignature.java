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
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.signature.AbstractASiCWithCAdESTestSignature;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public abstract class AbstractASiCSCAdESTestSignature extends AbstractASiCWithCAdESTestSignature {

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.ASICS;
	}

	@Override
	protected ASiCContainerType getExpectedASiCContainerType() {
		return ASiCContainerType.ASiC_S;
	}

	@Override
	protected void checkExtractedContent(ASiCContent asicContent) {
		super.checkExtractedContent(asicContent);

		assertNotNull(asicContent.getMimeTypeDocument());
		assertEquals(1, asicContent.getSignedDocuments().size());

		assertEquals(1, asicContent.getSignatureDocuments().size());

		DSSDocument signatureDocument = asicContent.getSignatureDocuments().get(0);
		assertEquals("META-INF/signature.p7s", signatureDocument.getName());
		assertNotNull(DSSUtils.toCMSSignedData(signatureDocument));

		assertFalse(Utils.isCollectionNotEmpty(asicContent.getManifestDocuments()));
		assertFalse(Utils.isCollectionNotEmpty(asicContent.getArchiveManifestDocuments()));
		assertFalse(Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()));
		assertFalse(Utils.isCollectionNotEmpty(asicContent.getUnsupportedDocuments()));
	}

	@Override
	protected DSSDocument getSignedData(ASiCContent extractResult) {
		List<DSSDocument> signedDocuments = extractResult.getSignedDocuments();
		assertEquals(1, signedDocuments.size());
		return signedDocuments.get(0);
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		DSSDocument documentToSign = getDocumentToSign();
		if (documentToSign != null && documentToSign.getMimeType() != null) {
			for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
				if (!signatureWrapper.isCounterSignature() && Utils.isStringEmpty(signatureWrapper.getContentHints())) {
					assertEquals(documentToSign.getMimeType(), MimeType.fromMimeTypeString(signatureWrapper.getMimeType()));
				} else {
					assertNull(signatureWrapper.getMimeType());
				}
			}
		}
	}

}
