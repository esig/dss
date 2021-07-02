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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * This class if a basic skeleton that is able to retrieve needed CRL data from
 * the contained list. The child need to retrieve the list of wrapped CRLs.
 */
@SuppressWarnings("serial")
public abstract class OfflineCRLSource extends OfflineRevocationSource<CRL> {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineCRLSource.class);

	private final List<CRLValidity> cachedValidCRLValidities = new ArrayList<>();

	/**
	 * The default constructor
	 */
	protected OfflineCRLSource() {
		super(new CRLTokenRefMatcher());
	}

	@Override
	public List<RevocationToken<CRL>> getRevocationTokens(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		Objects.requireNonNull(certificateToken, "The certificate to be verified cannot be null");
		Objects.requireNonNull(issuerToken, "The issuer of the certificate to be verified cannot be null");

		List<RevocationToken<CRL>> result = new ArrayList<>();

		List<CRLValidity> validCRLValiditiesForIssuer = getFromCachedCRLValidities(issuerToken);

		if (validCRLValiditiesForIssuer.isEmpty()) {

			final Set<EncapsulatedRevocationTokenIdentifier<CRL>> collectedBinaries = getAllRevocationBinaries();
			LOG.trace("--> OfflineCRLSource queried for {} contains: {} element(s).", certificateToken.getDSSIdAsString(), collectedBinaries.size());

			for (EncapsulatedRevocationTokenIdentifier<CRL> binary : collectedBinaries) {
				CRLBinary crlBinary = (CRLBinary) binary;
				try {
					CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, issuerToken);
					if (crlValidity.isValid()) {
						cachedValidCRLValidities.add(crlValidity);
						validCRLValiditiesForIssuer.add(crlValidity);
					}
				} catch (Exception e) {
					LOG.warn("Unable to retrieve the CRLValidity for CRL with ID '{}' : {}", crlBinary.asXmlId(), e.getMessage());
				}
			}
		}

		for (CRLValidity crlValidity : validCRLValiditiesForIssuer) {
			final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
			addRevocation(crlToken, crlValidity.getCrlBinary());
			result.add(crlToken);
		}

		LOG.trace("--> OfflineCRLSource found result(s) : {}", result.size());
		return result;
	}

	private List<CRLValidity> getFromCachedCRLValidities(CertificateToken issuerToken) {
		List<CRLValidity> result = new ArrayList<>();
		for (CRLValidity validity : cachedValidCRLValidities) {
			if (issuerToken.equals(validity.getIssuerToken())) {
				result.add(validity);
			}
		}
		return result;
	}

}
