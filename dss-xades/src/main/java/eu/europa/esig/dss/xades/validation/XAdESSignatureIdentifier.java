package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.SignatureIdentifier;

public final class XAdESSignatureIdentifier extends SignatureIdentifier {

	private static final long serialVersionUID = -6178082592350651519L;

	public XAdESSignatureIdentifier(XAdESSignature xadesSignature) {
		super(buildBinaries(xadesSignature));
	}
	
	private static byte[] buildBinaries(XAdESSignature xadesSignature) {
		final CertificateToken certificateToken = xadesSignature.getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		return buildSignatureIdentifier(xadesSignature.getSigningTime(), identifier, xadesSignature.getDAIdentifier(), xadesSignature.getSignatureValueBase64());
	}

}
