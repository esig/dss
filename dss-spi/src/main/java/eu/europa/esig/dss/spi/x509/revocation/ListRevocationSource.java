/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class allows to handle a list {@code OfflineRevocationSource}
 *
 * @param <R> implementation of revocation data token (CRL/OCSP)
 */
public class ListRevocationSource<R extends Revocation> implements MultipleRevocationSource<R> {

	private static final long serialVersionUID = -6284731668494875108L;

	/** List of revocation sources */
	private List<OfflineRevocationSource<R>> sources = new ArrayList<>();

	/**
	 * Default constructor
	 */
	public ListRevocationSource() {
		// empty
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
	 * @return whether the revocationSource has been added successfully
	 */
	public boolean add(OfflineRevocationSource<R> revocationSource) {
		if (revocationSource != null && !sources.contains(revocationSource)) {
			return sources.add(revocationSource);
		}
		return false;
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
	 * @return TRUE if the current source and its children are empty, FALSE if there is at least one revocation token
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
		Set<RevocationToken<R>> allTokens = new HashSet<>();
		for (OfflineRevocationSource<R> revocationSource : sources) {
			allTokens.addAll(revocationSource.getRevocationTokens(certificateToken, issuerCertificateToken));
		}
		return new ArrayList<>(allTokens);
	}

	/**
	 * Gets all revocation token binaries from all incorporated sources
	 *
	 * @return a list of {@link EncapsulatedRevocationTokenIdentifier}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getAllRevocationBinaries() {
		Set<EncapsulatedRevocationTokenIdentifier<R>> allBinaries = new HashSet<>();
		for (OfflineRevocationSource<R> revocationSource : sources) {
			allBinaries.addAll(revocationSource.getAllRevocationBinaries());
		}
		return new ArrayList<>(allBinaries);
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

	/**
	 * This method returns the number of set {@link RevocationSource}s
	 *
	 * @return the number of found {@link RevocationSource}
	 */
	public int getNumberOfSources() {
		return sources.size();
	}

}
