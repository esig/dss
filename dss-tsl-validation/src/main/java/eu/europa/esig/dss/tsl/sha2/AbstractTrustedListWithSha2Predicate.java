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
package eu.europa.esig.dss.tsl.sha2;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xades.definition.tsl.TrustedListNamespace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Date;
import java.util.function.Predicate;

/**
 * This is an abstract implementation of a Predicate for a Trusted List document with sha2 processing,
 * containing common utility methods for a Trusted List validation
 *
 */
public abstract class AbstractTrustedListWithSha2Predicate implements Predicate<DocumentWithSha2> {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractTrustedListWithSha2Predicate.class);

    /** The default sha2 digest algorithm defined in ETSI TS 119 612 */
    protected static final DigestAlgorithm SHA2_ALGORITHM = DigestAlgorithm.SHA256;

    /** The path to reach a tl:NextUpdate element */
    protected static final String NEXT_UPDATE_PATH = "./tl:SchemeInformation/tl:NextUpdate";

    static {
        DomUtils.registerNamespace(TrustedListNamespace.NS);
    }

    /**
     * Default constructor
     */
    protected AbstractTrustedListWithSha2Predicate() {
        // empty
    }

    /**
     * This method evaluates whether the sha2 digest match the original document
     *
     * @param documentWithSha2 {@link DocumentWithSha2} containing the original document and downloaded sha2 document
     * @return TRUE if the sha2 corresponding to the document match the digest of the cached content and
     *         no refresh is required, FALSE otherwise (if refresh is required for any reason)
     */
    @Override
    public abstract boolean test(DocumentWithSha2 documentWithSha2);

    /**
     * This method computes {@code Digest} on the given {@code DSSDocument}'s content
     *
     * @param document {@link DSSDocument} to compute digest on
     * @return {@link Digest}
     */
    protected Digest getOriginalDocumentDigest(DSSDocument document) {
        if (document == null) {
            return null;
        }
        byte[] digest = document.getDigestValue(SHA2_ALGORITHM);
        return new Digest(SHA2_ALGORITHM, digest);
    }

    /**
     * This method parses the {@code sha2Document} and returns the {@code Digest}
     *
     * @param sha2Document {@link DSSDocument} representing a sha2 document
     * @return {@link Digest}
     */
    protected Digest getSha2Digest(DSSDocument sha2Document) {
        if (sha2Document == null) {
            return null;
        }
        byte[] sha2DocumentBinaries = DSSUtils.toByteArray(sha2Document);
        // NOTE: not explicitly defined in the standard, but all known implementations use HEX encoded digest
        String sha2DocumentStr = new String(sha2DocumentBinaries);
        if (Utils.isHexEncoded(sha2DocumentStr)) {
            sha2DocumentBinaries = Utils.fromHex(sha2DocumentStr);
        }
        return new Digest(SHA2_ALGORITHM, sha2DocumentBinaries);
    }

    /**
     * This method retrieves a NextUpdate date value from the provided Trusted List document
     *
     * @param tlDocument {@link DSSDocument} representing a cached Trusted List
     * @return {@link Date} NextUpdate (when defined)
     */
    protected Date getNextUpdate(DSSDocument tlDocument) {
        if (!DomUtils.isDOM(tlDocument)) {
            LOG.warn("The document is not XML! Unable to extract NextUpdate.");
        }
        try {
            Document documentDom = DomUtils.buildDOM(tlDocument);
            Element nextUpdateElement = DomUtils.getElement(documentDom.getDocumentElement(), NEXT_UPDATE_PATH);
            if (nextUpdateElement != null) {
                String nextUpdate = nextUpdateElement.getTextContent();
                if (Utils.isStringNotEmpty(nextUpdate)) {
                    nextUpdate = Utils.trim(nextUpdate);
                    return DSSUtils.parseRFCDate(nextUpdate);
                } else if (LOG.isDebugEnabled()) {
                    LOG.debug("NextUpdate element has an empty content.");
                }
            } else {
                LOG.warn("No NextUpdate element found!");
            }
        } catch (Exception e) {
            String errorMessage = "An error occurred on NextUpdate extraction. Reason : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, e.getMessage());
            }
        }
        return null;
    }

}
