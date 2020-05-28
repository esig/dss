package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.SignatureIdentifier;

public class JAdESSignatureIdentifier extends SignatureIdentifier {

	private static final long serialVersionUID = 1L;

	public JAdESSignatureIdentifier(JAdESSignature signature) {
		super(buildBinaries(signature));
	}

	private static byte[] buildBinaries(JAdESSignature signature) {
		final CertificateToken certificateToken = signature.getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		return buildSignatureIdentifier(signature.getSigningTime(), identifier, signature.getJws().getEncodedHeader());
	}

}
