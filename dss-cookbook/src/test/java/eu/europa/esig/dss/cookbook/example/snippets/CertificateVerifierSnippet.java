/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.x509.AIASource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.OCSPFirstRevocationDataLoadingStrategy;
import org.slf4j.event.Level;

public class CertificateVerifierSnippet {

	public static void main(String[] args) {

		AIASource aiaSource = null;
		CertificateSource adjunctCertSource = null;
		CertificateSource trustedCertSource = null;
		CRLSource crlSource = null;
		OCSPSource ocspSource = null;

		// tag::demo[]

		CertificateVerifier cv = new CommonCertificateVerifier();

		// The AIA source is used to collect certificates from external resources (AIA)
		cv.setAIASource(aiaSource);

		// The adjunct certificate source is used to provide missing intermediate certificates
		// (not trusted certificates)
		cv.setAdjunctCertSources(adjunctCertSource);

		// The trusted certificate source is used to provide trusted certificates 
		// (the trust anchors where the certificate chain building should stop)
		cv.setTrustedCertSources(trustedCertSource);

		// The CRL Source to be used for external accesses (can be configured with a
		// cache,...)
		cv.setCrlSource(crlSource);

		// The OCSP Source to be used for external accesses (can be configured with a
		// cache,...)
		cv.setOcspSource(ocspSource);
		
		// Sets the default digest algorithm that will be used for digest calculation
		// of tokens used during the validation process. 
		// The values will be used in validation reports.
		// Default : DigestAlgorithm.SHA256
		cv.setDefaultDigestAlgorithm(DigestAlgorithm.SHA512);

		// Define the behavior to be followed by DSS in case of revocation checking for
		// certificates issued from an unsure source (DSS v5.4+)
		// Default : revocation check is disabled for unsure sources (security reasons)
		cv.setCheckRevocationForUntrustedChains(false);

		// DSS v5.4+ : The 3 below configurations concern the extension mode (LT/LTA
		// extension)

		// Defines a behavior in case of missing revocation data
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());

		// Defines a behavior if a TSU certificate chain is not covered with a
		// revocation data (timestamp generation time > CRL/OCSP production time).
		// Default : LogOnStatusAlert -> a WARN log
		cv.setAlertOnUncoveredPOE(new LogOnStatusAlert(Level.WARN));

		// Defines a behavior if a revoked certificate is present
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());

		// Defines a behavior if an invalid timestamp is found
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());
		
		// DSS v5.5+ : defines a behavior in case if there is no valid revocation
		// data with thisUpdate time after the best signature time
		// Example: if a signature was extended to T level then the obtained revocation 
		// must have thisUpdate time after production time of the signature timestamp.
		// Default : LogOnStatusAlert -> a WARN log
		cv.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert(Level.ERROR));

		// DSS 5.9+ :
		// Defines behavior in case if the signing certificate or its related POE(s) have been expired
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnExpiredSignature(new ExceptionOnStatusAlert());

		// DSS 5.9+ :
		// RevocationDataLoadingStrategy defines logic for loading OCSP or CRL data
		// Default : OCSPFirstRevocationDataLoadingStrategy -> loads OCSP first,
		// 			 if not available or the response is invalid, then tries to load CRL
		cv.setRevocationDataLoadingStrategy(new OCSPFirstRevocationDataLoadingStrategy());

		// end::demo[]

	}

}
