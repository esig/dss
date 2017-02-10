package eu.europa.esig.dss.xades.signature.en319132;

import java.io.File;
import java.util.Date;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.signature.AbstractTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESSignatureEn319132_Baseline_LTA_Test extends AbstractTestDocumentSignatureService<XAdESSignatureParameters> {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		SignerLocation location = new SignerLocation();
		location.setCountry("Luxembourg");
		location.setLocality("Kehlen");
		location.setStreet("Zone industrielle, 15");
		location.setPostalCode("L-8287");

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.setEn319132(true);
		signatureParameters.bLevel().addClaimedSignerRole("Test role");
		signatureParameters.bLevel().setSignerLocation(location);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new XAdESService(certificateVerifier);
		MockTSPSource tspSource = new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256));
		service.setTspSource(tspSource);
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected MockPrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
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
		return true;
	}

	@Override
	protected boolean isBaselineLTA() {
		return true;
	}
}
