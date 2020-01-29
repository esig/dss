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

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class allows to handle a list CRL source.
 *
 */
@SuppressWarnings("serial")
public class ListCRLSource implements CRLSource {

	private List<OfflineCRLSource> sources = new ArrayList<>();

	/**
	 * This is the constructor for this class, it allows to instantiate the list
	 * which will contain all {@code X509CRL}.
	 */
	public ListCRLSource() {
	}

	/**
	 * This constructor allows to initialize the list with a
	 * {@code OfflineCRLSource}.
	 *
	 * @param crlSource an offline crl source
	 */
	public ListCRLSource(OfflineCRLSource crlSource) {
		add(crlSource);
	}

	public void add(OfflineCRLSource crlSource) {
		sources.add(crlSource);
	}

	public void addAll(ListCRLSource listCRLSource) {
		addAll(listCRLSource.getSources());
	}

	public void addAll(List<OfflineCRLSource> crlSources) {
		sources.addAll(crlSources);
	}

	public List<OfflineCRLSource> getSources() {
		return sources;
	}

	public boolean isEmpty() {
		for (OfflineCRLSource offlineCRLSource : sources) {
			if (!offlineCRLSource.isEmpty()) {
				return false;
			}
		}
		return true;
	}

	public Set<RevocationOrigin> getRevocationOrigins(CRLBinary crlBinary) {
		Set<RevocationOrigin> result = new HashSet<>();
		for (OfflineCRLSource offlineCRLSource : sources) {
			Set<RevocationOrigin> revocationOrigins = offlineCRLSource.getRevocationOrigins(crlBinary);
			if (Utils.isCollectionNotEmpty(revocationOrigins)) {
				result.addAll(revocationOrigins);
			}
		}
		return result;
	}

	public Set<CRLToken> getAllCRLTokens() {
		Set<CRLToken> allTokens = new HashSet<>();
		for (OfflineCRLSource offlineCRLSource : sources) {
			if (offlineCRLSource instanceof SignatureCRLSource) {
				allTokens.addAll(((SignatureCRLSource) offlineCRLSource).getAllCRLTokens());
			}
		}
		return allTokens;
	}

	public List<CRLRef> findRefsForRevocationToken(CRLToken revocationToken) {
		List<CRLRef> result = new ArrayList<>();
		for (OfflineCRLSource offlineCRLSource : sources) {
			if (offlineCRLSource instanceof SignatureCRLSource) {
				result.addAll(((SignatureCRLSource) offlineCRLSource).findRefsForRevocationToken(revocationToken));
			}
		}
		return result;
	}

	public List<CRLRef> getReferencesForCRLIdentifier(CRLBinary revocationIdentifier) {
		List<CRLRef> result = new ArrayList<>();
		for (OfflineCRLSource offlineCRLSource : sources) {
			if (offlineCRLSource instanceof SignatureCRLSource) {
				result.addAll(((SignatureCRLSource) offlineCRLSource).getReferencesForCRLIdentifier(revocationIdentifier));
			}
		}
		return result;
	}

	public List<CRLRef> getOrphanCrlRefs() {
		List<CRLRef> result = new ArrayList<>();
		for (OfflineCRLSource offlineCRLSource : sources) {
			if (offlineCRLSource instanceof SignatureCRLSource) {
				List<CRLRef> allCrlRefs = ((SignatureCRLSource) offlineCRLSource).getAllCRLReferences();
				for (CRLRef crlRef : allCrlRefs) {
					if (getIdentifier(crlRef.getDigest()) == null) {
						addRef(result, crlRef);
					}
				}
			}
		}
		return result;
	}

	private void addRef(List<CRLRef> crlRefs, CRLRef crlRef) {
		int index = crlRefs.indexOf(crlRef);
		if (index == -1) {
			crlRefs.add(crlRef);
		} else {
			CRLRef storedCRLRef = crlRefs.get(index);
			for (RevocationRefOrigin origin : crlRef.getOrigins()) {
				storedCRLRef.addOrigin(origin);
			}
		}
	}

	public List<CRLBinary> getCRLBinaryList() {
		List<CRLBinary> result = new ArrayList<>();
		for (OfflineCRLSource offlineCRLSource : sources) {
			result.addAll(offlineCRLSource.getCRLBinaryList());
		}
		return result;
	}

	public CRLRef getCRLRefByDigest(Digest refDigest) {
		for (OfflineCRLSource offlineCRLSource : sources) {
			if (offlineCRLSource instanceof SignatureCRLSource) {
				CRLRef crlRef = ((SignatureCRLSource) offlineCRLSource).getCRLRefByDigest(refDigest);
				if (crlRef != null) {
					return crlRef;
				}
			}
		}
		return null;
	}

	public CRLBinary getIdentifier(Digest refDigest) {
		for (OfflineCRLSource offlineCRLSource : sources) {
			if (offlineCRLSource instanceof SignatureCRLSource) {
				CRLBinary binary = ((SignatureCRLSource) offlineCRLSource).getIdentifier(refDigest);
				if (binary != null) {
					return binary;
				}
			}
		}
		return null;
	}

	@Override
	public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		for (OfflineCRLSource crlSource : sources) {
			CRLToken crlToken = crlSource.getRevocationToken(certificateToken, issuerCertificateToken);
			if (crlToken != null && crlToken.isValid()) {
				return crlToken;
			}
		}
		return null;
	}

}
