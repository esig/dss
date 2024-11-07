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
package eu.europa.esig.dss.spi.validation.scope;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class finds a timestamp scope for a detached timestamp
 *
 */
public class DetachedTimestampScopeFinder extends AbstractSignatureScopeFinder implements TimestampScopeFinder {

    /** The data used to for message-imprint computation of a timestamp token */
    protected DSSDocument timestampedData;

    /**
     * Default constructor instantiating object with null timestamped data document
     */
    public DetachedTimestampScopeFinder() {
        // empty
    }

    /**
     * Sets the timestamped data
     *
     * @param timestampedData {@link DSSDocument}
     */
    public void setTimestampedData(DSSDocument timestampedData) {
        this.timestampedData = timestampedData;
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact()) {
            return getTimestampSignatureScopeForDocument(timestampedData);
        }
        return Collections.emptyList();
    }

    /**
     * Returns a timestamped {@code SignatureScope} for the given document
     *
     * @param document {@link DSSDocument} to get a signature scope for
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getTimestampSignatureScopeForDocument(DSSDocument document) {
        String documentName = document.getName();
        if (document instanceof DigestDocument) {
            return Arrays.asList(new DigestSignatureScope(Utils.isStringNotEmpty(documentName) ? documentName : "Digest document",
                    document));
        } else {
            return Arrays.asList(new FullSignatureScope(Utils.isStringNotEmpty(documentName) ? documentName : "Full document",
                    document));
        }
    }

}
