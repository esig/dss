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
package eu.europa.esig.dss.spi.x509.evidencerecord.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Creates an instance of {@code eu.europa.esig.dss.spi.x509.evidencerecord.DataObjectDigestBuilder}
 *
 */
public interface DataObjectDigestBuilderFactory {

    /**
     * Creates an instance of {@code DataObjectDigestBuilder} to build hash for the {@code document},
     * according to the given implementation, using a default digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash for
     * @return {@link DataObjectDigestBuilder}
     */
    DataObjectDigestBuilder create(DSSDocument document);

    /**
     * Creates an instance of {@code DataObjectDigestBuilder} to build hash for the {@code document},
     * according to the given implementation, using a provided {@code digestAlgorithm}
     *
     * @param document {@link DSSDocument} to compute hash for
     * @param digestAlgorithm {@link DigestAlgorithm} to use
     * @return {@link DataObjectDigestBuilder}
     */
    DataObjectDigestBuilder create(DSSDocument document, DigestAlgorithm digestAlgorithm);

}
