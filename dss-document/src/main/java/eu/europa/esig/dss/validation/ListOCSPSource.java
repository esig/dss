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
package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class allows to handle a list OCSP source.
 *
 */
@SuppressWarnings("serial")
public class ListOCSPSource implements OCSPSource {

	private List<OfflineOCSPSource> sources = new ArrayList<OfflineOCSPSource>();

	public ListOCSPSource() {
		// default constructor
	}

	/**
	 * This constructor allows to initialize the list with an
	 * {@code OfflineOCSPSource}.
	 *
	 * @param ocspSource an offline ocsp source
	 */
	public ListOCSPSource(final OfflineOCSPSource ocspSource) {
		add(ocspSource);
	}

	public void add(OfflineOCSPSource ocspSource) {
		sources.add(ocspSource);
	}

	public void addAll(ListOCSPSource listOCSPSources) {
		addAll(listOCSPSources.getSources());
	}

	public void addAll(List<OfflineOCSPSource> ocspSources) {
		sources.addAll(ocspSources);
	}

	public List<OfflineOCSPSource> getSources() {
		return sources;
	}

	public boolean isEmpty() {
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (!offlineOCSPSource.isEmpty()) {
				return false;
			}
		}
		return true;
	}

	public Set<RevocationOrigin> getRevocationOrigins(OCSPResponseBinary identifier) {
		Set<RevocationOrigin> result = new HashSet<RevocationOrigin>();
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			Set<RevocationOrigin> revocationOrigins = offlineOCSPSource.getRevocationOrigins(identifier);
			if (Utils.isCollectionNotEmpty(revocationOrigins)) {
				result.addAll(revocationOrigins);
			}
		}
		return result;
	}

	public Set<OCSPToken> getAllOCSPTokens() {
		Set<OCSPToken> allTokens = new HashSet<OCSPToken>();
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (offlineOCSPSource instanceof SignatureOCSPSource) {
				allTokens.addAll(((SignatureOCSPSource) offlineOCSPSource).getAllOCSPTokens());
			}
		}
		return allTokens;
	}

	public List<OCSPRef> findRefsForRevocationToken(OCSPToken revocationToken) {
		List<OCSPRef> result = new ArrayList<OCSPRef>();
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (offlineOCSPSource instanceof SignatureOCSPSource) {
				result.addAll(((SignatureOCSPSource) offlineOCSPSource).findRefsForRevocationToken(revocationToken));
			}
		}
		return result;
	}

	public List<OCSPRef> getReferencesForOCSPIdentifier(OCSPResponseBinary revocationIdentifier) {
		List<OCSPRef> result = new ArrayList<OCSPRef>();
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (offlineOCSPSource instanceof SignatureOCSPSource) {
				result.addAll(((SignatureOCSPSource) offlineOCSPSource).getReferencesForOCSPIdentifier(revocationIdentifier));
			}
		}
		return result;
	}

	public List<OCSPRef> getOrphanOCSPRefs() {
		List<OCSPRef> result = new ArrayList<OCSPRef>();
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (offlineOCSPSource instanceof SignatureOCSPSource) {
				List<OCSPRef> allOCSPRefs = ((SignatureOCSPSource) offlineOCSPSource).getOrphanOCSPRefs();
				for (OCSPRef ocspRef : allOCSPRefs) {
					if (getIdentifier(ocspRef.getDigest()) == null) {
						addRef(result, ocspRef);
					}
				}
			}
		}
		return result;
	}

	private void addRef(List<OCSPRef> ocspRefs, OCSPRef ocspRef) {
		int index = ocspRefs.indexOf(ocspRef);
		if (index == -1) {
			ocspRefs.add(ocspRef);
		} else {
			OCSPRef storedOCSPRef = ocspRefs.get(index);
			for (RevocationRefOrigin origin : ocspRef.getOrigins()) {
				storedOCSPRef.addOrigin(origin);
			}
		}
	}

	public List<OCSPResponseBinary> getOCSPResponsesList() {
		List<OCSPResponseBinary> result = new ArrayList<OCSPResponseBinary>();
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			result.addAll(offlineOCSPSource.getOCSPResponsesList());
		}
		return result;
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		for (OCSPSource ocspSource : sources) {
			OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, issuerCertificateToken);
			if (ocspToken != null && ocspToken.isValid()) {
				return ocspToken;
			}
		}
		return null;
	}

	public OCSPResponseBinary getIdentifier(Digest refDigest) {
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (offlineOCSPSource instanceof SignatureOCSPSource) {
				OCSPResponseBinary identifier = ((SignatureOCSPSource) offlineOCSPSource).getIdentifier(refDigest);
				if (identifier != null) {
					return identifier;
				}
			}
		}
		return null;
	}

	public OCSPResponseBinary getIdentifier(OCSPRef ocspRef) {
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (offlineOCSPSource instanceof SignatureOCSPSource) {
				OCSPResponseBinary identifier = ((SignatureOCSPSource) offlineOCSPSource).getIdentifier(ocspRef);
				if (identifier != null) {
					return identifier;
				}
			}
		}
		return null;
	}

	public OCSPRef getOCSPRefByDigest(Digest refDigest) {
		for (OfflineOCSPSource offlineOCSPSource : sources) {
			if (offlineOCSPSource instanceof SignatureOCSPSource) {
				OCSPRef ref = ((SignatureOCSPSource) offlineOCSPSource).getOCSPRefByDigest(refDigest);
				if (ref != null) {
					return ref;
				}
			}
		}
		return null;
	}

}
