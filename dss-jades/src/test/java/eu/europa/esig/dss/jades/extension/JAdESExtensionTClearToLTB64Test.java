package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSConverter;
import eu.europa.esig.dss.jades.signature.AbstractJAdESTestSignature;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JAdESExtensionTClearToLTB64Test extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;

	@BeforeEach
	public void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
		signatureParameters.setBase64UrlEncodedEtsiUComponents(false);
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument signedDocument = super.sign();

		signatureParameters.setBase64UrlEncodedEtsiUComponents(true);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);

		Exception exception = assertThrows(DSSException.class,
				() -> service.extendDocument(signedDocument, signatureParameters));
		assertEquals("Extension is not possible! The encoding of 'etsiU' "
				+ "components shall match! Use jadesSignatureParameters.setBase64UrlEncodedEtsiUComponents(false)",
				exception.getMessage());

		DSSDocument convertedDocument = JWSConverter.fromEtsiUWithClearJsonToBase64UrlIncorporation(signedDocument);

		DSSDocument extendedDocument = service.extendDocument(convertedDocument, signatureParameters);
		assertNotNull(extendedDocument);
		return extendedDocument;
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
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
