package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRefIdentifier;

public final class OCSPRefIdentifier extends RevocationRefIdentifier {

	private static final long serialVersionUID = 3113937346660525679L;

	protected OCSPRefIdentifier(OCSPRef ocspRef) {
		super(getDigest(ocspRef));
	}
	
	private static Digest getDigest(OCSPRef ocspRef) {
		if (ocspRef.getDigest() != null) {
			return ocspRef.getDigest();
		}
		
		byte[] bytes;
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (ocspRef.getProducedAt() != null) {
				dos.writeLong(ocspRef.getProducedAt().getTime());
			}
			ResponderId responderId = ocspRef.getResponderId();
			if (responderId != null) {
				if (responderId.getKey() != null) {
					dos.write(responderId.getKey());
				}
				if (responderId.getName() != null) {
					dos.writeChars(responderId.getName());
				}
			}
			dos.flush();
			bytes = baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Cannot build DSS ID for the OCSP Ref.", e);
		}
		return new Digest(DIGEST_ALGO, DSSUtils.digest(DIGEST_ALGO, bytes));
	}

}
