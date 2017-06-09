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

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.AbstractTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBEnvelopedWithReferenceTest extends AbstractTestDocumentSignatureService<XAdESSignatureParameters> {

	private static final Logger logger = LoggerFactory.getLogger(XAdESLevelBEnvelopedWithReferenceTest.class);
	
	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sampleWithPlaceOfSignature.xml"));

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
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
		
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new XAdESService(certificateVerifier);

	}
	
	@Test
	public void signAndVerify() throws IOException {
		final DSSDocument signedDocument = sign();

		assertNotNull(signedDocument.getName());
		assertNotNull(DSSUtils.toByteArray(signedDocument));
		assertNotNull(signedDocument.getMimeType());

		logger.info("=================== VALIDATION =================");

		signedDocument.save("target/" + signedDocument.getName());

		try {
			byte[] byteArray = Utils.toByteArray(signedDocument.openStream());
			onDocumentSigned(byteArray);
			if (logger.isDebugEnabled()) {
				logger.debug(new String(byteArray));
			}
		} catch (Exception e) {
			logger.error("Cannot display file content", e);
		}

		checkMimeType(signedDocument);

		Reports reports = getValidationReport(signedDocument);
		// reports.setValidateXml(true);
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		verifyDiagnosticData(diagnosticData);

		SimpleReport simpleReport = reports.getSimpleReport();
		verifySimpleReport(simpleReport);

		DetailedReport detailedReport = reports.getDetailedReport();
		verifyDetailedReport(detailedReport);
		
		checkSignedDocument();
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
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected MockPrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}
	
	private void checkSignedDocument() {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
	
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new File("target/sampleWithPlaceOfSignature-signed-xades-baseline-b.xml"));
			
			XPathFactory f = XPathFactory.newInstance();
			XPath xPath = f.newXPath();
			xPath.setNamespaceContext(new Name());
			Node node = (Node) xPath.evaluate("test:root/data[@id='data1']", doc, XPathConstants.NODE);
	
			Init.init();
			Canonicalizer c14n = Canonicalizer.getInstance("http://www.w3.org/2001/10/xml-exc-c14n#");
			byte c14nBytes[] = c14n.canonicalizeSubtree(node);
	
			Assert.assertEquals("AdGdZ+/VQVVvC9yzL4Yj8iRK33cQBiRW2UpKGMswdZQ=", Base64.encode(MessageDigest.getInstance("SHA-256").digest(c14nBytes)));
			
			node = (Node) xPath.evaluate("test:root/data[@id='data2']", doc, XPathConstants.NODE);
	
			Init.init();
			c14n = Canonicalizer.getInstance("http://www.w3.org/2001/10/xml-exc-c14n#");
			c14nBytes = c14n.canonicalizeSubtree(node);
	
			Assert.assertEquals("R69a3Im5463c09SuOrn9Sfly9h9LxVxSqg/0CVumJjA=", Base64.encode(MessageDigest.getInstance("SHA-256").digest(c14nBytes)));
		} catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	private static final class Name implements NamespaceContext {
		public Iterator getPrefixes(String namespaceURI) {
			// TODO Auto-generated method stub
			return null;
		}
	
		public String getPrefix(String namespaceURI) {
			// TODO Auto-generated method stub
			return null;
		}
	
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
