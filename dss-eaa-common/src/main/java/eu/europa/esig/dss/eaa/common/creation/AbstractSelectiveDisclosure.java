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
package eu.europa.esig.dss.eaa.common.creation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;

import java.util.EnumMap;

/**
 * Abstract implementation of an EAA Disclosure
 *
 */
public abstract class AbstractSelectiveDisclosure implements SelectiveDisclosure {

    private static final long serialVersionUID = -1362240576992224151L;

    /** Cached map containing computed digest values */
    private final EnumMap<DigestAlgorithm, Digest> digestMap = new EnumMap<>(DigestAlgorithm.class);

    /**
     * Default constructor
     */
    protected AbstractSelectiveDisclosure() {
        //empty
    }

    @Override
    public Digest getDigest(DigestAlgorithm digestAlgorithm) {
        if (digestAlgorithm == null) {
            return new Digest(); // empty digest
        }
        return digestMap.computeIfAbsent(digestAlgorithm, d -> computeDigest(digestAlgorithm));
    }

    /**
     * Computes digest according to the rules for the given EAA presentation type
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on the hash computation
     * @return {@link Digest}
     */
    protected abstract Digest computeDigest(DigestAlgorithm digestAlgorithm);

}
