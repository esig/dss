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

import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBWithCustomCommitmentTypeTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private List<CommitmentType> commitmentTypeIndications;

	@BeforeEach
	public void init() throws Exception {
		service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		
		MockCommitmentType commitmentTypeApproval = new MockCommitmentType("http://nowina.lu/approved");
		commitmentTypeApproval.setQualifier(ObjectIdentifierQualifier.OID_AS_URI);
		commitmentTypeApproval.setDescription("Approved");
		commitmentTypeApproval.setDocumentReferences("http://nowina.lu/approved.pdf", "https://uri.etsi.org/01903/v1.2.2/ts_101903v010202p.pdf");
		
		MockCommitmentType commitmentTypeCreation = new MockCommitmentType("http://nowina.lu/created");
		commitmentTypeCreation.setDocumentReferences();
		
		commitmentTypeIndications = Arrays.asList(commitmentTypeApproval, commitmentTypeCreation);

		signatureParameters.bLevel().setCommitmentTypeIndications(commitmentTypeIndications);
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		String xmlContent = new String(byteArray);
		assertTrue(xmlContent.contains(":Identifier Qualifier=\"OIDAsURI\""));
		assertTrue(xmlContent.contains(":Description>"));
		assertTrue(xmlContent.contains(":DocumentationReferences>"));
		assertTrue(xmlContent.contains(":DocumentationReference>"));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
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
	
	private static class MockCommitmentType implements CommitmentType {

		private static final long serialVersionUID = -8371847686841801005L;

		private final String uri;
		private ObjectIdentifierQualifier qualifier;
		private String description;
		private String[] documentReferences;
		
		private MockCommitmentType(String uri) {
			this.uri = uri;
		}
		
		public void setQualifier(ObjectIdentifierQualifier qualifier) {
			this.qualifier = qualifier;
		}

		public void setDescription(String description) {
			this.description = description;
		}

		public void setDocumentReferences(String... documentReferences) {
			this.documentReferences = documentReferences;
		}
		
		@Override
		public String getOid() {
			return null;
		}

		@Override
		public String getUri() {
			return uri;
		}

		@Override
		public String getDescription() {
			return description;
		}

		@Override
		public String[] getDocumentationReferences() {
			return documentReferences;
		}

		@Override
		public ObjectIdentifierQualifier getQualifier() {
			return qualifier;
		}
		
	}
	
}
