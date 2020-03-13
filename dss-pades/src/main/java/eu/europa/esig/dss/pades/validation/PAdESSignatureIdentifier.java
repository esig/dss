package eu.europa.esig.dss.pades.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.ByteRange;
import eu.europa.esig.dss.validation.SignatureIdentifier;

public final class PAdESSignatureIdentifier extends SignatureIdentifier {

	private static final long serialVersionUID = -7672798196825794558L;

	public PAdESSignatureIdentifier(PAdESSignature padesSignature) {
		super(buildBinaries(padesSignature));
	}
	
	private static byte[] buildBinaries(PAdESSignature padesSignature) {
		final CertificateToken certificateToken = padesSignature.getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		return SignatureIdentifier.buildSignatureIdentifier(padesSignature.getSigningTime(), identifier, getDigestOfByteRange(padesSignature.getPdfRevision()));
	}

	private static String getDigestOfByteRange(PdfSignatureRevision pdfSignatureRevision) {
		ByteRange signatureByteRange = pdfSignatureRevision.getByteRange();
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			baos.write(signatureByteRange.toString().getBytes());
			return DSSUtils.getMD5Digest(baos.toByteArray());
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read byteRange : %s", signatureByteRange));
		}
	}

}
