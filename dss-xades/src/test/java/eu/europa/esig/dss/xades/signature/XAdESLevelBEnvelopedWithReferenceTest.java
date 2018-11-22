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

import java.io.File;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.SantuarioInitializer;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBEnvelopedWithReferenceTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		SantuarioInitializer.init();

		documentToSign = new FileDocument(new File("src/test/resources/sampleWithPlaceOfSignature.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setXPathLocationString("//placeOfSignature");

		List<DSSReference> dssReferences = new ArrayList<DSSReference>();
		DSSReference reference1 = new DSSReference();
		reference1.setContents(documentToSign);
		reference1.setId("REF-ID1");
		reference1.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		reference1.setUri("#data1");
		List<DSSTransform> transforms1 = new ArrayList<DSSTransform>();
		DSSTransform transform1 = new DSSTransform();
		transform1.setAlgorithm(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		transforms1.add(transform1);
		reference1.setTransforms(transforms1);
		dssReferences.add(reference1);

		DSSReference reference2 = new DSSReference();
		reference2.setContents(documentToSign);
		reference2.setId("REF-ID2");
		reference2.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		reference2.setUri("#data2");
		List<DSSTransform> transforms2 = new ArrayList<DSSTransform>();
		DSSTransform transform2 = new DSSTransform();
		transform2.setAlgorithm(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		transforms2.add(transform2);
		reference2.setTransforms(transforms2);
		dssReferences.add(reference2);

		signatureParameters.setReferences(dssReferences);

		service = new XAdESService(getCompleteCertificateVerifier());
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

			Canonicalizer c14n = Canonicalizer.getInstance("http://www.w3.org/2001/10/xml-exc-c14n#");
			byte c14nBytes[] = c14n.canonicalizeSubtree(node);

			Assert.assertEquals("AdGdZ+/VQVVvC9yzL4Yj8iRK33cQBiRW2UpKGMswdZQ=", Base64.encode(MessageDigest.getInstance("SHA-256").digest(c14nBytes)));

			node = (Node) xPath.evaluate("root/data[@id='data2']", doc, XPathConstants.NODE);

			c14n = Canonicalizer.getInstance("http://www.w3.org/2001/10/xml-exc-c14n#");
			c14nBytes = c14n.canonicalizeSubtree(node);

			Assert.assertEquals("R69a3Im5463c09SuOrn9Sfly9h9LxVxSqg/0CVumJjA=", Base64.encode(MessageDigest.getInstance("SHA-256").digest(c14nBytes)));
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	@Override
	protected void getOriginalDocument(DSSDocument signedDocument, DiagnosticData diagnosticData) {
		// Ignored sampleWithPlaceOfSignature itself is not covered
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
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
		public Iterator getPrefixes(String namespaceURI) {
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
