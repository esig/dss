package eu.europa.dss.signature.policy.validation.items;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.dss.signature.policy.RevReq;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

public class RevReqValidator {

	private static final Logger LOG = LoggerFactory.getLogger(RevReqValidator.class);
	
	private RevReq revReq;
	private CertificateToken target;

	public RevReqValidator(RevReq revReq, CertificateToken target) {
		this.revReq = revReq;
		this.target = target;
	}

	public boolean validate() {
		return !isRevoked();
	}

	private boolean isRevoked() {
		try {
			switch (revReq.getEnuRevReq()) {
			case noCheck: return false;
			case other: return true;
			case crlCheck: return isRevokedCrl();
			case ocspCheck: return isRevokedOcsp();
			case bothCheck: return isRevokedCrl() && isRevokedOcsp();
			case eitherCheck:
				try {
					return isRevokedOcsp();
				} catch (Exception e) {
					LOG.debug("Unexpected error while checking OCSP, trying CRL", e);
					return isRevokedCrl();
				}
			}
		} catch (Exception e) {
			LOG.debug("Unexpected error while checking Revocation", e);
		}
		return true;
	}

	private boolean isRevokedOcsp() {
		Set<RevocationToken> revocationTokens = target.getRevocationTokens();
		if (revocationTokens != null) {
			for (RevocationToken revocationToken : revocationTokens) {
				if (revocationToken.getStatus() != null && revocationToken instanceof OCSPToken) {
					return !revocationToken.getStatus();
				}
			}
		}
		
		// TODO in case both are required, DSS needs to fetch whatever is missing
		throw new DSSException("No OCSP response found");
	}

	private boolean isRevokedCrl() {
		Set<RevocationToken> revocationTokens = target.getRevocationTokens();
		if (revocationTokens != null) {
			for (RevocationToken revocationToken : revocationTokens) {
				if (revocationToken.getStatus() != null && revocationToken instanceof CRLToken) {
					return !revocationToken.getStatus();
				}
			}
		}

		// TODO in case both are required, DSS needs to fetch whatever is missing
		throw new DSSException("No CRL response found");
	}
}
