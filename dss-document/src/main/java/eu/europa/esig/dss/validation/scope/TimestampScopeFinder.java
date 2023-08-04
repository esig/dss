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
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.List;

/**
 * This interface is used to find a signature scope for a timestamp
 *
 */
public interface TimestampScopeFinder {

    /**
     * This method returns a timestamp scope for the given {@code TimestampToken}
     *
     * @param timestampToken {@link TimestampToken} to get signature scope for
     * @return a list of {@link SignatureScope}s
     */
    List<SignatureScope> findTimestampScope(TimestampToken timestampToken);

    /**
     * Sets the default DigestAlgorithm to use for {@code SignatureScope} digest computation
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to use
     */
    void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm);

}
