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

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.MultipleRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

import java.util.ArrayList;
import java.util.List;

/**
 * This class allows to handle a list {@code OfflineRevocationSource}
 *
 */
public class ListRevocationSource<R extends Revocation> implements MultipleRevocationSource<R> {

	private static final long serialVersionUID = -6284731668494875108L;

	/** List of revocation sources */
	private List<OfflineRevocationSource<R>> sources = new ArrayList<>();

	/**
	 * Default constructor
	 */
	public ListRevocationSource() {
	}

	/**
	 * This constructor allows to initialize the list with an
	 * {@code OfflineRevocationSource}.
	 *
	 * @param revocationSource {@link OfflineRevocationSource}
	 */
	public ListRevocationSource(final OfflineRevocationSource<R> revocationSource) {
		add(revocationSource);
	}

	/**
	 * Adds the {@code revocationSource} to the list by keeping old values
	 *
	 * @param revocationSource {@link OfflineRevocationSource} to add
	 */
	public void add(OfflineRevocationSource<R> revocationSource) {
		sources.add(revocationSource);
	}

	/**
	 * Adds all sources from a {@code listRevocationSource} to the list by keeping old values
	 *
	 * @param listRevocationSource {@link ListRevocationSource} to add
	 */
	public void addAll(ListRevocationSource<R> listRevocationSource) {
		addAll(listRevocationSource.getSources());
	}

	/**
	 * Adds all {@code revocationSources} to the list by keeping old values
	 *
	 * @param revocationSources a list of {@link OfflineRevocationSource}s to add
	 */
	public void addAll(List<OfflineRevocationSource<R>> revocationSources) {
		sources.addAll(revocationSources);
	}

	/**
	 * Gets a list of all embedded sources
	 *
	 * @return a list of {@link OfflineRevocationSource}s
	 */
	public List<OfflineRevocationSource<R>> getSources() {
		return sources;
	}

	/**
	 * Checks if the current ListRevocationSource and its children are empty
	 *
	 * @return TRUE if the current source and its children are empty, FALSE if there is at leats one revocation token
	 */
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

	/**
	 * Gets all revocation token binaries from all incorporated sources
	 *
	 * @return a list of {@link EncapsulatedRevocationTokenIdentifier}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getAllRevocationBinaries() {
		List<EncapsulatedRevocationTokenIdentifier<R>> result = new ArrayList<>();
		for (OfflineRevocationSource<R> revocationSource : sources) {
			result.addAll(revocationSource.getAllRevocationBinaries());
		}
		return result;
	}

	/**
	 * Gets the incorporated {@code EncapsulatedRevocationTokenIdentifier} corresponding
	 * to the provided {@code reference}
	 *
	 * @param reference {@link RevocationRef} to get revocation token identifier for
	 * @return {@link EncapsulatedRevocationTokenIdentifier}
	 */
	public EncapsulatedRevocationTokenIdentifier<R> findBinaryForReference(RevocationRef<R> reference) {
		for (OfflineRevocationSource<R> revocationSource : sources) {
			EncapsulatedRevocationTokenIdentifier<R> tokenIdentifier = revocationSource.findBinaryForReference(reference);
			if (tokenIdentifier != null) {
				return tokenIdentifier;
			}
		}
		return null;
	}

	/**
	 * Checks if the source does not contain revocation identifiers matching to the {@code reference}
	 *
	 * @param reference {@link RevocationRef} to check
	 * @return TRUE if the reference is orphan, FALSE otherwise
	 */
	public boolean isOrphan(RevocationRef<R> reference) {
		for (OfflineRevocationSource<R> revocationSource : sources) {
			if (!revocationSource.isOrphan(reference)) {
				return false;
			}
		}
		return true;
	}

}
