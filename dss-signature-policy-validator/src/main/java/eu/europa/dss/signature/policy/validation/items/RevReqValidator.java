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

public class RevReqValidator implements ItemValidator {

	private static final Logger LOG = LoggerFactory.getLogger(RevReqValidator.class);
	
	private RevReq revReq;
	private CertificateToken target;

	public RevReqValidator(RevReq revReq, CertificateToken target) {
		this.revReq = revReq;
		this.target = target;
	}

	public boolean validate() {
		return checkRevocation();
	}

	private boolean checkRevocation() {
		try {
			switch (revReq.getEnuRevReq()) {
			case noCheck: return true;
			case other: return false;
			case crlCheck: return checkCrlRevocation();
			case ocspCheck: return checkOcspRevocation();
			case bothCheck: return checkOcspRevocation() && checkCrlRevocation();
			case eitherCheck:
				try {
					return checkOcspRevocation();
				} catch (Exception e) {
					LOG.debug("Unexpected error while checking OCSP, trying CRL", e);
					return checkCrlRevocation();
				}
			}
		} catch (Exception e) {
			LOG.debug("Unexpected error while checking Revocation", e);
		}
		return false;
	}

	private boolean checkOcspRevocation() {
		Set<RevocationToken> revocationTokens = target.getRevocationTokens();
		if (revocationTokens != null) {
			for (RevocationToken revocationToken : revocationTokens) {
				if (revocationToken instanceof OCSPToken && revocationToken.isValid() && revocationToken.getStatus() != null) {
					return revocationToken.getStatus();
				}
			}
		}
		
		// TODO in case both are required, DSS needs to fetch whatever is missing
		throw new DSSException("No OCSP response found");
	}

	private boolean checkCrlRevocation() {
		Set<RevocationToken> revocationTokens = target.getRevocationTokens();
		if (revocationTokens != null) {
			for (RevocationToken revocationToken : revocationTokens) {
				if (revocationToken instanceof CRLToken && revocationToken.isValid() && revocationToken.getStatus() != null) {
					return revocationToken.getStatus();
				}
			}
		}

		// TODO in case both are required, DSS needs to fetch whatever is missing
		throw new DSSException("No CRL response found");
	}
}
