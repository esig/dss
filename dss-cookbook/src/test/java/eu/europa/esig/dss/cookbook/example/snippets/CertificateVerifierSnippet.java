package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPSource;

public class CertificateVerifierSnippet {

	public static void main(String[] args) {

		DataLoader dataLoader = null;
		CertificateSource adjunctCertSource = null;
		CertificateSource trustedCertSource = null;
		CRLSource crlSource = null;
		OCSPSource ocspSource = null;

		// tag::demo[]

		CertificateVerifier cv = new CommonCertificateVerifier();

		// This data loader is used to collect certificates from external resources
		// (AIA)
		cv.setDataLoader(dataLoader);

		// This certificate source is used to provide missing intermediate certificates
		// (not trusted certificates)
		cv.setAdjunctCertSource(adjunctCertSource);

		// This certificate source is used to provide trusted certificates (the trust
		// anchors where the certificate chain building should stop)
		cv.setTrustedCertSource(trustedCertSource);

		// The CRL Source to be used for external accesses (can be configured with a
		// cache,...)
		cv.setCrlSource(crlSource);

		// The OCSP Source to be used for external accesses (can be configured with a
		// cache,...)
		cv.setOcspSource(ocspSource);

		// Define the behavior to be followed by DSS in case of revocation checking for
		// certificates issued from an unsure source (DSS v 5.4+)
		// Default : revocation check is disabled for unsure sources (security reasons)
		cv.setCheckRevocationForUntrustedChains(false);

		// DSS v 5.4+ : The 3 below configurations concern the extension mode (LT/LTA
		// extension)

		// DSS throws an exception by default in case of missing revocation data
		// Default : true
		cv.setExceptionOnMissingRevocationData(true);

		// DSS throws an exception if a TSU certificate chain is not covered with a
		// revocation data (timestamp generation time > CRL/OCSP production time).
		// Default : false
		cv.setExceptionOnUncoveredPOE(true);

		// DSS interrupts by default the extension process if a revoked certificate is
		// present
		// Default : true
		cv.setExceptionOnRevokedCertificate(true);

		// DSS stops the extension process if an invalid timestamp is met
		// Default : true
		cv.setExceptionOnInvalidTimestamp(true);

		// end::demo[]

	}

}
