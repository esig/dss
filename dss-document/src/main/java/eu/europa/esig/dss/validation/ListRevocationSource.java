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
import java.util.List;

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.MultipleRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

/**
 * This class allows to handle a list {@code OfflineRevocationSource}
 *
 */
@SuppressWarnings("serial")
public class ListRevocationSource<R extends Revocation> implements MultipleRevocationSource<R> {

	private List<OfflineRevocationSource<R>> sources = new ArrayList<>();

	public ListRevocationSource() {
		// default constructor
	}

	/**
	 * This constructor allows to initialize the list with an
	 * {@code OfflineRevocationSource}.
	 *
	 * @param revocationSource an offline revocation source
	 */
	public ListRevocationSource(final OfflineRevocationSource<R> revocationSource) {
		add(revocationSource);
	}

	public void add(OfflineRevocationSource<R> revocationSource) {
		sources.add(revocationSource);
	}

	public void addAll(ListRevocationSource<R> listRevocationSource) {
		addAll(listRevocationSource.getSources());
	}

	public void addAll(List<OfflineRevocationSource<R>> revocationSources) {
		sources.addAll(revocationSources);
	}

	public List<OfflineRevocationSource<R>> getSources() {
		return sources;
	}

	public boolean isEmpty() {
		for (OfflineRevocationSource<R> revocationSource : sources) {
			if (!revocationSource.isEmpty()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public List<RevocationToken<R>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		List<RevocationToken<R>> result = new ArrayList<>();
		for (OfflineRevocationSource<R> revocationSource : sources) {
			result.addAll(revocationSource.getRevocationTokens(certificateToken, issuerCertificateToken));
		}
		return result;
	}

	public List<EncapsulatedRevocationTokenIdentifier> getAllRevocationBinaries() {
		List<EncapsulatedRevocationTokenIdentifier> result = new ArrayList<>();
		for (OfflineRevocationSource<R> revocationSource : sources) {
			result.addAll(revocationSource.getAllRevocationBinaries());
		}
		return result;
	}

	public EncapsulatedRevocationTokenIdentifier findBinaryForReference(RevocationRef<R> reference) {
		for (OfflineRevocationSource<R> revocationSource : sources) {
			EncapsulatedRevocationTokenIdentifier tokenIdentifier = revocationSource.findBinaryForReference(reference);
			if (tokenIdentifier != null) {
				return tokenIdentifier;
			}
		}
		return null;
	}

	public boolean isOrphan(RevocationRef<R> ref) {
		for (OfflineRevocationSource<R> revocationSource : sources) {
			if (!revocationSource.isOrphan(ref)) {
				return false;
			}
		}
		return true;
	}

}
