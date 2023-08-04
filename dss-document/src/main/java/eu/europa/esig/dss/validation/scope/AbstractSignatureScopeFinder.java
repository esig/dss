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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

/**
 * The abstract class for {@code SignatureScope} finding
 *
 */
public abstract class AbstractSignatureScopeFinder {

	/**
	 * Default constructor instantiating the object with default values
	 */
	protected AbstractSignatureScopeFinder() {
		// empty
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

	/**
	 * Creates a {@code DSSDocument} from given {@code binaries}
	 *
	 * @param binaries {@link Digest} to create an in-memory document instance from
	 * @return {@link DSSDocument}
	 */
	protected DSSDocument createInMemoryDocument(byte[] binaries) {
		return new InMemoryDocument(binaries);
	}

	/**
	 * Creates a {@code DSSDocument} from given {@code digest}
	 *
	 * @param digest {@link Digest} to create a digest document instance from
	 * @return {@link DSSDocument}
	 */
	protected DSSDocument createDigestDocument(Digest digest) {
		return new DigestDocument(digest.getAlgorithm(), Utils.toBase64(digest.getValue()));
	}

}
