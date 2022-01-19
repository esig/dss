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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Abstract class that helps to implement an OCSPSource with an already loaded list of BasicOCSPResp
 *
 */
@SuppressWarnings("serial")
public abstract class OfflineOCSPSource extends OfflineRevocationSource<OCSP> {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineOCSPSource.class);

	/**
	 * Default constructor
	 */
	protected OfflineOCSPSource() {
		super(new OCSPTokenRefMatcher());
	}

	@Override
	public List<RevocationToken<OCSP>> getRevocationTokens(CertificateToken certificate, CertificateToken issuer) {
		Objects.requireNonNull(certificate, "The certificate to be verified cannot be null");
		Objects.requireNonNull(issuer, "The issuer of the certificate to be verified cannot be null");

		List<RevocationToken<OCSP>> result = new ArrayList<>();

		Set<RevocationToken<OCSP>> allRevocationTokens = getAllRevocationTokens();
		for (RevocationToken<OCSP> revocationToken : allRevocationTokens) {
			if (certificate.getDSSIdAsString().equals(revocationToken.getRelatedCertificateId())) {
				result.add(revocationToken);
			}
		}

		if (Utils.isCollectionEmpty(result)) {
			final Set<EncapsulatedRevocationTokenIdentifier<OCSP>> collectedBinaries = getAllRevocationBinaries();
			LOG.trace("--> OfflineOCSPSource queried for {} contains: {} element(s).", certificate.getDSSIdAsString(), collectedBinaries.size());
			for (EncapsulatedRevocationTokenIdentifier<OCSP> binary : collectedBinaries) {
				OCSPResponseBinary ocspBinary = (OCSPResponseBinary) binary;
				BasicOCSPResp basicOCSPResp = ocspBinary.getBasicOCSPResp();
				SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(basicOCSPResp, certificate, issuer);
				if (latestSingleResponse != null) {
					OCSPToken ocspToken = new OCSPToken(basicOCSPResp, latestSingleResponse, certificate, issuer);
					addRevocation(ocspToken, ocspBinary);
					result.add(ocspToken);
				}
			}
		}

		LOG.trace("--> OfflineOCSPSource found result(s) : {}", result.size());
		return result;
	}

}
