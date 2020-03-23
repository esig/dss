package eu.europa.esig.dss.spi.x509.revocation.crl;

import java.util.Arrays;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationTokenRefMatcher;

public class CRLTokenRefMatcher implements RevocationTokenRefMatcher<CRL> {

	@Override
	public boolean match(RevocationToken<CRL> token, RevocationRef<CRL> reference) {
		final CRLToken crlToken = (CRLToken) token;
		final CRLRef crlRef = (CRLRef) reference;

		if (crlRef.getDigest() != null) {
			return matchByDigest(crlToken, crlRef.getDigest());
		} else {
			throw new DSSException("Digest is mandatory for comparison");
		}
	}

	private boolean matchByDigest(CRLToken crlToken, Digest digestToFind) {
		return Arrays.equals(digestToFind.getValue(), crlToken.getDigest(digestToFind.getAlgorithm()));
	}

}
