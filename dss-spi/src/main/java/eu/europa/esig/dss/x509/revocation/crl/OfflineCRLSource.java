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
package eu.europa.esig.dss.x509.revocation.crl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.CRLBinaryIdentifier;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;

/**
 * This class if a basic skeleton that is able to retrieve needed CRL data from
 * the contained list. The child need to retrieve the list of wrapped CRLs.
 */
@SuppressWarnings("serial")
public abstract class OfflineCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineCRLSource.class);

	/**
	 * This {@code HashMap} contains not validated CRL binaries. When the validation passes, the entry will be removed.
	 * The key is the SHA256 digest of the CRL binaries.
	 */
	protected List<CRLBinaryIdentifier> crlsBinaryList = new ArrayList<CRLBinaryIdentifier>();

	/**
	 * This {@code HashMap} contains the {@code CRLValidity} object for each
	 * {@code CRLBinaryIdentifier}. It is used for performance reasons.
	 */
	private Map<CRLBinaryIdentifier, CRLValidity> crlValidityMap = new HashMap<CRLBinaryIdentifier, CRLValidity>();

	private Map<CertificateToken, CRLToken> validCRLTokenList = new HashMap<CertificateToken, CRLToken>();

	@Override
	public final CRLToken getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		if (certificateToken == null) {
			throw new NullPointerException();
		}

		final CRLToken validCRLToken = validCRLTokenList.get(certificateToken);
		if (validCRLToken != null) {
			return validCRLToken;
		}

		if (issuerToken == null) {
			return null;
		}

		final List<CRLBinaryIdentifier> crlBinariesToAdd = new ArrayList<CRLBinaryIdentifier>(); // used to store revocation data from different sources
		final CRLValidity bestCRLValidity = getBestCrlValidityEntry(certificateToken, issuerToken, crlBinariesToAdd);
		if (bestCRLValidity == null) {
			return null;
		}

		final CRLToken crlToken = new CRLToken(certificateToken, bestCRLValidity);
		validCRLTokenList.put(certificateToken, crlToken);
		// store tokens with different origins
		for (CRLBinaryIdentifier crlBinary : crlBinariesToAdd) {
			storeCRLToken(crlBinary, crlToken);
		}
		return crlToken;
	}

	/**
	 * This method returns the best {@code CRLValidity} containing the most
	 * recent {@code X509CRL}.
	 *
	 * @param certificateToken
	 *            {@code CertificateToken} for with the CRL is issued
	 * @param issuerToken
	 *            {@code CertificateToken} representing the signing certificate
	 *            of the CRL
	 * @return {@code CRLValidity}
	 */
	private CRLValidity getBestCrlValidityEntry(final CertificateToken certificateToken, final CertificateToken issuerToken, List<CRLBinaryIdentifier> crlBinaries) {

		CRLValidity bestCRLValidity = null;
		Date bestX509UpdateDate = null;

		for (CRLBinaryIdentifier crlEntry : crlsBinaryList) {
			final CRLValidity crlValidity = getCrlValidity(crlEntry, issuerToken);
			if (crlValidity == null || !crlValidity.isValid()) {
				continue;
			}
			if (issuerToken.getPublicKey().equals(crlValidity.getIssuerToken().getPublicKey())) {
				// check the overlapping of the [thisUpdate, nextUpdate] from the CRL and
				// [notBefore, notAfter] from the X509Certificate
				final Date thisUpdate = crlValidity.getThisUpdate();
				final Date nextUpdate = crlValidity.getNextUpdate();
				final Date notAfter = certificateToken.getNotAfter();
				final Date notBefore = certificateToken.getNotBefore();
				boolean periodAreIntersecting = thisUpdate.before(notAfter) && (nextUpdate != null && nextUpdate.after(notBefore));
				if (!periodAreIntersecting) {
					LOG.warn("The CRL was not issued during the validity period of the certificate! Certificate: {}", certificateToken.getDSSIdAsString());
					continue;
				}

				if ((bestX509UpdateDate == null) || thisUpdate.after(bestX509UpdateDate)) {
					bestCRLValidity = crlValidity;
					bestX509UpdateDate = thisUpdate;
					bestX509UpdateDate = thisUpdate;
					crlBinaries.clear();
					crlBinaries.add(crlEntry);
				}
			}
		}
		return bestCRLValidity;
	}

	/**
	 * This method returns {@code CRLValidity} object based on the given
	 * {@code X509CRL}. The check of the validity of the CRL is performed.
	 * 
	 * @param key
	 *            the key to use in maps
	 * @param crlBinaries
	 *            the CRL binaries to be checked
	 * @param issuerToken
	 *            {@code CertificateToken} issuer of the CRL
	 * @return returns updated {@code CRLValidity} object
	 */
	private CRLValidity getCrlValidity(final CRLBinaryIdentifier crlBinary, final CertificateToken issuerToken) {
		CRLValidity crlValidity = crlValidityMap.get(crlBinary);
		if (crlValidity == null) {
			try (InputStream is = new ByteArrayInputStream(crlBinary.getBinaries())) {
				crlValidity = CRLUtils.isValidCRL(is, issuerToken);
				if (crlValidity.isValid()) {
					crlValidityMap.put(crlBinary, crlValidity);
					// crlsMap.remove(key);
				}
			} catch (IOException e) {
				LOG.error("Unable to parse CRL", e);
			}
		}
		if (crlValidity.getRevocationOrigin() == null) {
			crlValidity.setRevocationOrigin(crlBinary.getOrigin());
		}
		return crlValidity;
	}

	/**
	 * @return unmodifiable {@code Collection}
	 */
	public Collection<byte[]> getContainedX509CRLs() {
		Collection<byte[]> binaries = new ArrayList<byte[]>();
		for (CRLBinaryIdentifier crlBinary : crlsBinaryList) {
			binaries.add(crlBinary.getBinaries());
		}
		return Collections.unmodifiableCollection(binaries);
	}

	protected void addCRLBinary(byte[] binaries, RevocationOrigin origin) {
		CRLBinaryIdentifier crlBinary = CRLBinaryIdentifier.build(binaries, origin);
		addCRLBinary(crlBinary);
	}

	protected void addCRLBinary(CRLBinaryIdentifier crlBinary) {
		if (!crlsBinaryList.contains(crlBinary) && !crlValidityMap.containsKey(crlBinary)) {
			crlsBinaryList.add(crlBinary);
		}
	}
	
	protected void storeCRLToken(final CRLBinaryIdentifier crlBinary, final CRLToken crlToken) {
		// do nothing
	}

}
