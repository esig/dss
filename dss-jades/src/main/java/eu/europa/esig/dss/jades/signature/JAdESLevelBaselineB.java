package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.validation.CustomJsonWebSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class JAdESLevelBaselineB {
	
	private CertificateVerifier certificateVerifier;
	
	public JAdESLevelBaselineB(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}
	
	byte[] getDataToSign(final DSSDocument document, final JAdESSignatureParameters parameters) {
		String concatenationResult = getDataToSignConcatenatedString(document, parameters);
		return JAdESUtils.getAsciiBytes(concatenationResult);
	}
	
	String getDataToSignConcatenatedString(final DSSDocument document, final JAdESSignatureParameters parameters) {
		CustomJsonWebSignature jws = buildHeader(parameters);
		setPayload(jws, document);
		return JAdESUtils.concatenate(jws.getEncodedHeader(), jws.getEncodedPayload());
	}
	
	protected CustomJsonWebSignature buildHeader(final JAdESSignatureParameters parameters) {
		JOSEHeaderBuilder joseHeaderBuilder = new JOSEHeaderBuilder(certificateVerifier, parameters);
		return joseHeaderBuilder.build();
	}
	
	private void setPayload(final CustomJsonWebSignature jws, final DSSDocument document) {
		jws.setPayloadBytes(DSSUtils.toByteArray(document));
	}

}
