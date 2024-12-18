/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESSignedAssertionTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private DSSDocument documentToSign;

	private Date signingDate;
	private TimestampToken contentTimestamp;
	private String signedAssertion;

	@BeforeEach
	void init() throws Exception {
		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		signedAssertion = new String(DSSUtils.toByteArray(getClass().getResourceAsStream("/sample-saml-assertion.xml")));

		signingDate = new Date();
		contentTimestamp = service.getContentTimestamp(documentToSign, getSignatureParameters());
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		// Stateless mode
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		 // sign with Level LTA to check that correct ds:Signature element (NOT in signed assertion) is extended
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.bLevel().setSignedAssertions(Arrays.asList(signedAssertion));
		if (contentTimestamp != null) {
			signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
		}
		return signatureParameters;
	}
	
	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		assertEquals(1, diagnosticData.getAllSignatures().size());

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		// verify that SAML assertions were included successfully in signature
		List<String> signedAssertions = getSignatureParameters().bLevel().getSignedAssertions();
		for (int i = 0; i < signedAssertions.size(); i++) {
			Document expected = DomUtils.buildDOM(signedAssertions.get(i));
			Document extracted = DomUtils.buildDOM(signature.getSignedAssertions().get(i).getRole());
			assertTrue(expected.isEqualNode(extracted));
		}
	}
	protected void checkReferences(Document documentDOM) {
		NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(documentDOM);
		// validate only the first
		Element signatureElement = (Element) signatureNodeList.item(0);
		NodeList referenceNodeList = DomUtils.getNodeList(signatureElement, XMLDSigPath.SIGNED_INFO_REFERENCE_PATH);
		NodeList dataObjectFormatNodeList = DomUtils.getNodeList(signatureElement, new XAdES132Path().getDataObjectFormat());
		for (int j = 0; j < referenceNodeList.getLength(); j++) {
			Element reference = (Element) referenceNodeList.item(j);

			String referenceType = reference.getAttribute(XMLDSigAttribute.TYPE.getAttributeName());
			String referenceUri = reference.getAttribute(XMLDSigAttribute.URI.getAttributeName());
			assertNotNull(referenceUri);

			String referenceId = reference.getAttribute(XMLDSigAttribute.ID.getAttributeName());
			assertNotNull(referenceId);

			if ((DomUtils.startsFromHash(referenceUri) || DomUtils.isXPointerQuery(referenceUri)) &&
					(new XAdES132Path().getSignedPropertiesUri().equals(referenceType) ||
							new XAdES132Path().getCounterSignatureUri().equals(referenceType))) {
				continue;
			}

			boolean relatedDataObjectFormatFound = false;
			for (int k = 0; k < dataObjectFormatNodeList.getLength(); k++) {
				Element dataObjectFormat = (Element) dataObjectFormatNodeList.item(k);
				String objectReference = dataObjectFormat.getAttribute(XAdES132Attribute.OBJECT_REFERENCE.getAttributeName());
				if (referenceId.equals(DomUtils.getId(objectReference))) {
					relatedDataObjectFormatFound = true;
					break;
				}
			}
			assertTrue(relatedDataObjectFormatFound);
		}
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
