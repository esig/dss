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
package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.OriginalIdentifierProvider;
import eu.europa.esig.dss.validation.TokenIdentifierProvider;

/**
 * The abstract class for {@code SignatureScope} finding
 *
 */
public abstract class AbstractSignatureScopeFinder {

	/** The DigestAlgorithm to use for digest computation */
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	/** The TokenIdentifierProvider to be used for extraction of token IDs */
	private TokenIdentifierProvider tokenIdentifierProvider = new OriginalIdentifierProvider();

	/**
	 * Returns the used {@code DigestAlgorithm}
	 *
	 * @return {@link DigestAlgorithm}
	 */
	protected DigestAlgorithm getDefaultDigestAlgorithm() {
		return defaultDigestAlgorithm;
	}

	/**
	 * Sets the default DigestAlgorithm to use for {@code SignatureScope} digest computation
	 *
	 * @param defaultDigestAlgorithm {@link DigestAlgorithm} to use
	 */
	public void setDefaultDigestAlgorithm(DigestAlgorithm defaultDigestAlgorithm) {
		this.defaultDigestAlgorithm = defaultDigestAlgorithm;
	}

	/**
	 * Gets the {@code TokenIdentifierProvider}
	 *
	 * @return {@link TokenIdentifierProvider}
	 */
	protected TokenIdentifierProvider getTokenIdentifierProvider() {
		return tokenIdentifierProvider;
	}

	/**
	 * Sets the {@code TokenIdentifierProvider} to be used for identifiers extraction
	 *
	 * @param tokenIdentifierProvider {@link TokenIdentifierProvider}
	 */
	public void setTokenIdentifierProvider(TokenIdentifierProvider tokenIdentifierProvider) {
		this.tokenIdentifierProvider = tokenIdentifierProvider;
	}

	/**
	 * Gets digest of a document
	 *
	 * @param document {@link DSSDocument}
	 * @return {@link Digest}
	 */
	protected Digest getDigest(DSSDocument document) {
		return new Digest(defaultDigestAlgorithm, Utils.fromBase64(document.getDigest(defaultDigestAlgorithm)));
	}

	/**
	 * Gets digest of a binaries
	 *
	 * @param dataBytes a byte array
	 * @return {@link Digest}
	 */
	protected Digest getDigest(byte[] dataBytes) {
		return new Digest(defaultDigestAlgorithm, DSSUtils.digest(defaultDigestAlgorithm, dataBytes));
	}

	/**
	 * Checks if the given signature represents an ASiC-S container
	 *
	 * @param advancedSignature {@link AdvancedSignature} to check
	 * @return TRUE if the signature is ASiC-S, FALSE otherwise
	 */
	protected boolean isASiCSArchive(AdvancedSignature advancedSignature) {
		return Utils.isCollectionNotEmpty(advancedSignature.getContainerContents());
	}

	/**
	 * Checks if the given signature represents an ASiC-E container
	 *
	 * @param advancedSignature {@link AdvancedSignature} to check
	 * @return TRUE if the signature is ASiC-E, FALSE otherwise
	 */
	protected boolean isASiCEArchive(AdvancedSignature advancedSignature) {
		return advancedSignature.getManifestFile() != null;
	}

}
