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

import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.SantuarioInitializer;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import org.apache.xml.security.transforms.Transforms;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESLevelBEnvelopedWithReferenceTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		SantuarioInitializer.init();

		documentToSign = new FileDocument(new File("src/test/resources/sampleWithPlaceOfSignature.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setXPathLocationString("//placeOfSignature");

		List<DSSReference> dssReferences = new ArrayList<>();
		DSSReference reference1 = new DSSReference();
		reference1.setContents(documentToSign);
		reference1.setId("REF-ID1");
		reference1.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
		reference1.setUri("#data1");
		List<DSSTransform> transforms1 = new ArrayList<>();
		CanonicalizationTransform transform1 = new CanonicalizationTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		transforms1.add(transform1);
		reference1.setTransforms(transforms1);
		dssReferences.add(reference1);

		DSSReference reference2 = new DSSReference();
		reference2.setContents(documentToSign);
		reference2.setId("REF-ID2");
		reference2.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
		reference2.setUri("#data2");
		List<DSSTransform> transforms2 = new ArrayList<>();
		CanonicalizationTransform transform2 = new CanonicalizationTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		transforms2.add(transform2);
		reference2.setTransforms(transforms2);
		dssReferences.add(reference2);

		signatureParameters.setReferences(dssReferences);

		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		try {
			Document doc = DomUtils.buildDOM(byteArray);

			XPathFactory f = XPathFactory.newInstance();
			XPath xPath = f.newXPath();
			xPath.setNamespaceContext(new Name());
			Node node = (Node) xPath.evaluate("root/data[@id='data1']", doc, XPathConstants.NODE);

			byte[] c14nBytes = XMLCanonicalizer.createInstance("http://www.w3.org/2001/10/xml-exc-c14n#").canonicalize(node);

			assertEquals("AdGdZ+/VQVVvC9yzL4Yj8iRK33cQBiRW2UpKGMswdZQ=",
					Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(c14nBytes)));

			node = (Node) xPath.evaluate("root/data[@id='data2']", doc, XPathConstants.NODE);

			c14nBytes = XMLCanonicalizer.createInstance("http://www.w3.org/2001/10/xml-exc-c14n#").canonicalize(node);

			assertEquals("R69a3Im5463c09SuOrn9Sfly9h9LxVxSqg/0CVumJjA=",
					Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(c14nBytes)));
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// Ignored sampleWithPlaceOfSignature itself is not covered
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
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

	private static final class Name implements NamespaceContext {
		
		@Override
		public Iterator<String> getPrefixes(String namespaceURI) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public String getPrefix(String namespaceURI) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public String getNamespaceURI(String prefix) {
			if ("xades".equals(prefix)) {
				return "http://uri.etsi.org/01903/v1.3.2#";
			} else if ("ds".equals(prefix)) {
				return "http://www.w3.org/2000/09/xmldsig#";
			} else if ("test".equals(prefix)) {
				return "http://www.w3.org/2000/09/xmltest#";
			}
			// "http://uri.etsi.org/19132/v1.1.1#"
			return null;
		}
		
	}
}
