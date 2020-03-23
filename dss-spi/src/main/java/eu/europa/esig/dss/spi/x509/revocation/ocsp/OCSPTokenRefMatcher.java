package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.util.Arrays;

import org.bouncycastle.asn1.ocsp.ResponderID;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationTokenRefMatcher;

public class OCSPTokenRefMatcher implements RevocationTokenRefMatcher<OCSP> {

	@Override
	public boolean match(RevocationToken<OCSP> token, RevocationRef<OCSP> reference) {
		final OCSPToken ocspToken = (OCSPToken) token;
		final OCSPRef ocspRef = (OCSPRef) reference;

		if (ocspRef.getDigest() != null) {
			return matchByDigest(ocspToken, ocspRef.getDigest());
		} else {
			return matchByProperties(ocspToken, ocspRef);
		}
	}

	private boolean matchByDigest(OCSPToken ocspToken, Digest digestToFind) {
		return Arrays.equals(digestToFind.getValue(), ocspToken.getDigest(digestToFind.getAlgorithm()));
	}

	private boolean matchByProperties(OCSPToken ocspToken, OCSPRef ocspRef) {
		if (ocspRef.getProducedAt().equals(ocspToken.getProductionDate())) {
			ResponderID tokenResponderId = ocspToken.getBasicOCSPResp().getResponderId().toASN1Primitive();
			ResponderId refResponderId = ocspRef.getResponderId();
			if (matchByKeyHash(tokenResponderId, refResponderId) || matchByName(tokenResponderId, refResponderId)) {
				return true;
			}
		}
		return false;
	}

	private boolean matchByKeyHash(ResponderID tokenResponderId, ResponderId refResponderId) {
		return refResponderId.getSki() != null && Arrays.equals(refResponderId.getSki(), tokenResponderId.getKeyHash());
	}

	private boolean matchByName(ResponderID tokenResponderId, ResponderId refResponderId) {
		return refResponderId.getX500Principal() != null && tokenResponderId.getName() != null
				&& refResponderId.getX500Principal().equals(DSSASN1Utils.toX500Principal(tokenResponderId.getName()));
	}

}
