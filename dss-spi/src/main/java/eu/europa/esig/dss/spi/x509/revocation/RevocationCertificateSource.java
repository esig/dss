package eu.europa.esig.dss.spi.x509.revocation;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;

/**
 * Represents a certificate source present into a revocation token
 *
 */
@SuppressWarnings("serial")
public abstract class RevocationCertificateSource extends TokenCertificateSource {
	
	@Override
	public List<CertificateRef> getAllCertificateRefs() {
		// not implemented by default
		return Collections.emptyList();
	}

}
