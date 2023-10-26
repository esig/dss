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
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.trustedlist.TrustedListUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.validation.Schema;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class TrustedListSigningTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private static TrustedListUtils trustedListUtils = TrustedListUtils.getInstance();

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
		service = new XAdESService(getOfflineCertificateVerifier());

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setEn319132(false);

		final List<DSSReference> references = new ArrayList<>();

		DSSReference dssReference = new DSSReference();
		dssReference.setId("xml_ref_id");
		dssReference.setUri("");
		dssReference.setContents(documentToSign);
		dssReference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

		final List<DSSTransform> transforms = new ArrayList<>();

		EnvelopedSignatureTransform signatureTransform = new EnvelopedSignatureTransform();
		transforms.add(signatureTransform);

		CanonicalizationTransform dssTransform = new CanonicalizationTransform(getCanonicalizationMethod());
		transforms.add(dssTransform);

		dssReference.setTransforms(transforms);
		references.add(dssReference);

		signatureParameters.setReferences(references);
	}
	
	@Override
	protected String getCanonicalizationMethod() {
		return CanonicalizationMethod.EXCLUSIVE;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		try {
			Document doc = DomUtils.getSecureDocumentBuilderFactory()
					.newDocumentBuilder().parse(new ByteArrayInputStream(byteArray));

			NodeList signlist = doc.getDocumentElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			assertEquals(1, signlist.getLength());

			NodeList refList = ((Element) signlist.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
			assertEquals(2, refList.getLength());

			NodeList transormfList = ((Element) refList.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Transform");
			assertEquals(2, transormfList.getLength());

			assertEquals("http://www.w3.org/2000/09/xmldsig#enveloped-signature", ((Element) transormfList.item(0)).getAttribute("Algorithm"));

			assertEquals("http://www.w3.org/2001/10/xml-exc-c14n#", ((Element) transormfList.item(1)).getAttribute("Algorithm"));
			
			NodeList objectlist = ((Element) signlist.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Object");
			assertEquals(1, objectlist.getLength());
			
			NodeList qualProplist = ((Element) objectlist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "QualifyingProperties");
			assertEquals(1, qualProplist.getLength());
			
			NodeList signProplist = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
			assertEquals(1, signProplist.getLength());
			
			NodeList signSigProplist = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedSignatureProperties");
			assertEquals(1, signSigProplist.getLength());
			
			NodeList signCertlist = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SigningCertificate");
			assertEquals(1, signCertlist.getLength());
			
			NodeList signCertV2list = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SigningCertificateV2");
			assertEquals(0, signCertV2list.getLength());
			
			unmarshallingTester(doc);

		} catch (Exception e) {
			fail(e);
		}
	}

	@SuppressWarnings("unchecked")
	private void unmarshallingTester(Document doc) throws JAXBException, SAXException {
		JAXBContext jc = trustedListUtils.getJAXBContext();
		Schema schema = trustedListUtils.getSchema();
		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<TrustStatusListType> unmarshalled = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(doc);
		assertNotNull(unmarshalled);
		
		Marshaller marshaller = jc.createMarshaller();
		marshaller.setSchema(schema);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String tlString = sw.toString();
		
		JAXBElement<TrustStatusListType> unmarshalled2 = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(new StringReader(tlString));
		assertNotNull(unmarshalled2);
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

}
