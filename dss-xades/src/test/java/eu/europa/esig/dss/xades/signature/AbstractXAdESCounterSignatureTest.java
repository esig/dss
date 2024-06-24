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

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.AbstractCounterSignatureTest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.validationreport.jaxb.SAMessageDigestType;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractXAdESCounterSignatureTest extends AbstractCounterSignatureTest<XAdESSignatureParameters, 
				XAdESTimestampParameters, XAdESCounterSignatureParameters> {
	
	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		
		assertTrue(new String(byteArray).contains(XAdES132Element.COUNTER_SIGNATURE.getTagName()));
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeTypeEnum.XML;
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

	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);

		Set<SignatureWrapper> allCounterSignatures = diagnosticData.getAllCounterSignatures();
		assertTrue(Utils.isCollectionNotEmpty(allCounterSignatures));
		for (SignatureWrapper signatureWrapper : allCounterSignatures) {
			boolean counterSignatureReferenceFound = false;
			boolean counterSignedSignatureValueFound = false;
			for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
				if (DigestMatcherType.COUNTER_SIGNATURE.equals(digestMatcher.getType())) {
					counterSignatureReferenceFound = true;
				} else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
					counterSignedSignatureValueFound = true;
				}
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
			assertTrue(counterSignatureReferenceFound);
			assertTrue(counterSignedSignatureValueFound);
		}
	}

	@Override
	protected void validateETSIMessageDigest(SAMessageDigestType md) {
		assertNull(md);
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {
			
			SignatureWrapper signatureById = diagnosticData.getSignatureById(signatureId);
			if (signatureById.isCounterSignature()) {
				continue;
			}

			List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
			assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
			
			List<DSSDocument> originalDocuments = getOriginalDocuments();
			for (DSSDocument original : originalDocuments) {
				assertTrue(documentPresent(original, retrievedOriginalDocuments), "Unable to retrieve the original document " + original.getName());
			}
		}
	}

	protected boolean documentPresent(DSSDocument original, List<DSSDocument> retrievedDocuments) {
		boolean found = false;
		boolean toBeCanonicalized = MimeTypeEnum.XML.equals(original.getMimeType()) || MimeTypeEnum.HTML.equals(original.getMimeType());
		String originalDigest = getDigest(original, toBeCanonicalized);
		for (DSSDocument retrieved : retrievedDocuments) {
			String retrievedDigest = getDigest(retrieved, toBeCanonicalized);
			if (Utils.areStringsEqual(originalDigest, retrievedDigest)) {
				found = true;
				break;
			}
		}
		return found;
	}

	protected String getDigest(DSSDocument doc, boolean toBeCanonicalized) {
		byte[] byteArray = DSSUtils.toByteArray(doc);
		if (toBeCanonicalized && DomUtils.isDOM(doc)) {
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				// we canonicalize to ignore the header (which is not covered by the signature)
				Canonicalizer c14n = Canonicalizer.getInstance(getCanonicalizationMethod());
				c14n.canonicalize(byteArray, baos, true);
				byteArray = baos.toByteArray();
			} catch (XMLSecurityException | IOException e) {
				// Not always able to canonicalize (more than one file can be covered (XML +
				// something else) )
			}
		}
		// LOG.info("Bytes : {}", new String(byteArray));
		return Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, byteArray));
	}

}
