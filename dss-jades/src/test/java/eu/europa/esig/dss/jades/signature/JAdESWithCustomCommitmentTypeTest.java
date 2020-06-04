package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class JAdESWithCustomCommitmentTypeTest extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;

	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signingDate = new Date();
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		
		MockCommitmentType commitmentTypeApproval = new MockCommitmentType("http://nowina.lu/approved");
		commitmentTypeApproval.setDescription("Approved");
		commitmentTypeApproval.setDocumentReferences("http://nowina.lu/approved.pdf", "https://uri.etsi.org/01903/v1.2.2/ts_101903v010202p.pdf");
		
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(commitmentTypeApproval));
		
		return signatureParameters;
	}
	
	@Override
	protected void checkCommitmentTypeIndications(DiagnosticData diagnosticData) {
		super.checkCommitmentTypeIndications(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlCommitmentTypeIndication> commitmentTypeIndications = signature.getCommitmentTypeIndications();
		assertEquals(1, commitmentTypeIndications.size());
		XmlCommitmentTypeIndication commitmentTypeIndication = commitmentTypeIndications.get(0);
		assertEquals(2, commitmentTypeIndication.getDocumentationReferences().size());
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	private class MockCommitmentType implements CommitmentType {
		
		private final String uri;
		private String description;
		private String[] documentReferences;
		
		public MockCommitmentType(String uri) {
			this.uri = uri;
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
			return null;
		}
		
	}

}
