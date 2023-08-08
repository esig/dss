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
package eu.europa.esig.dss.asic.xades.signature.asics;

import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCTestSignature;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCSXAdESTestSignature
		extends AbstractASiCTestSignature<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

	@Override
	protected MimeType getExpectedMime() {
		return MimeTypeEnum.ASICS;
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		return SignatureLevel.XAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
	}

	@Override
	protected ASiCWithXAdESContainerExtractor getContainerExtractor(DSSDocument document) {
		return new ASiCWithXAdESContainerExtractor(document);
	}

	@Override
	protected void checkExtractedContent(ASiCContent asicContent) {
		super.checkExtractedContent(asicContent);

		assertNotNull(asicContent.getMimeTypeDocument());
		assertEquals(1, asicContent.getSignedDocuments().size());
		assertEquals(1, asicContent.getRootLevelSignedDocuments().size());

		assertEquals(1, asicContent.getSignatureDocuments().size());

		DSSDocument signatureDocument = asicContent.getSignatureDocuments().get(0);
		assertEquals("META-INF/signatures.xml", signatureDocument.getName());
		assertTrue(DomUtils.isDOM(signatureDocument));

		Document document = DomUtils.buildDOM(signatureDocument);
		assertEquals("XAdESSignatures", document.getDocumentElement().getLocalName());
		assertEquals("http://uri.etsi.org/02918/v1.2.1#", document.getDocumentElement().getNamespaceURI());

		boolean sigFound = false;
		NodeList childNodes = document.getDocumentElement().getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node node = childNodes.item(i);
			if (node instanceof Element) {
				Element element = (Element) node;
				assertEquals("Signature", element.getLocalName());
				sigFound = true;
			}
		}
		assertTrue(sigFound);

		assertFalse(Utils.isCollectionNotEmpty(asicContent.getManifestDocuments()));
		assertFalse(Utils.isCollectionNotEmpty(asicContent.getArchiveManifestDocuments()));
		assertFalse(Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()));
		assertFalse(Utils.isCollectionNotEmpty(asicContent.getUnsupportedDocuments()));
	}

	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		super.checkContainerInfo(diagnosticData);

		assertNotNull(diagnosticData.getContainerInfo());
		assertEquals(ASiCContainerType.ASiC_S, diagnosticData.getContainerType());
		assertNotNull(diagnosticData.getMimetypeFileContent());
		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));

		List<String> contentFiles = diagnosticData.getContainerInfo().getContentFiles();
		assertEquals(1, contentFiles.size());

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			boolean contentFileFound = false;
			for (XmlSignatureScope signatureScope : signatureWrapper.getSignatureScopes()) {
				if (contentFiles.get(0).equals(signatureScope.getName())) {
					contentFileFound = true;
				}
			}
			assertTrue(contentFileFound);
		}
	}
	
}
