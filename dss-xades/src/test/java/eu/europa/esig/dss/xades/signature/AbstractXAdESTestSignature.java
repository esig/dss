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
package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public abstract class AbstractXAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<XAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractXAdESTestSignature.class);

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		// In case of enveloped / internally detached signatures, we don't know the
		// whole XML structure
		if (!SignaturePackaging.ENVELOPED.equals(getSignatureParameters().getSignaturePackaging())
				&& !SignaturePackaging.INTERNALLY_DETACHED.equals(getSignatureParameters().getSignaturePackaging())) {
			try {
				DSSXMLUtils.validateAgainstXSD(new InMemoryDocument(byteArray));
			} catch (Exception e) {
				LOG.error("Invalid XML", e);
				fail(e.getMessage());
			}
		}

		// Check for duplicate ids
		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(new InMemoryDocument(byteArray)));
		
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel)
				|| SignatureLevel.XAdES_C.equals(signatureLevel) || SignatureLevel.XAdES_X.equals(signatureLevel)
				|| SignatureLevel.XAdES_XL.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel);
	}

}
