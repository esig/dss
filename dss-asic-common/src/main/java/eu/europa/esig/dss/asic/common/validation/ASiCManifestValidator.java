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
package eu.europa.esig.dss.asic.common.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Performs validation of an ASiC Manifest entries
 *
 */
public class ASiCManifestValidator {

    private static final Logger LOG = LoggerFactory.getLogger(ASiCManifestValidator.class);

    /** Manifest to validate */
    private final ManifestFile manifest;

    /** A list of documents covered by the manifest */
    private final List<DSSDocument> signedDocuments;

    /**
     * The default constructor
     *
     * @param manifest {@link ManifestFile}
     * @param signedDocuments a list of {@link DSSDocument}s
     */
    public ASiCManifestValidator(final ManifestFile manifest, final List<DSSDocument> signedDocuments) {
        Objects.requireNonNull(manifest, "ManifestFile must be defined!");
        this.manifest = manifest;
        this.signedDocuments = signedDocuments;
    }

    /**
     * Validates the manifest entries
     * @return list of validated {@link ManifestEntry}s
     */
    public List<ManifestEntry> validateEntries() {
        List<ManifestEntry> manifestEntries = manifest.getEntries();
        if (Utils.isCollectionEmpty(signedDocuments)) {
            // no signed data to validate on
            return manifestEntries;
        }
        for (ManifestEntry entry : manifestEntries) {
            if (entry.getDigest() != null) {
                DSSDocument signedDocument = DSSUtils.getDocumentWithName(signedDocuments, entry.getFileName());
                if (signedDocument != null) {
                    entry.setFound(true);
                    byte[] computedDigest = signedDocument.getDigestValue(entry.getDigest().getAlgorithm());
                    if (Arrays.equals(entry.getDigest().getValue(), computedDigest)) {
                        entry.setIntact(true);
                    } else {
                        LOG.warn("Digest value doesn't match for signed data with name '{}'", entry.getFileName());
                        LOG.warn("Expected : '{}'", Utils.toBase64(entry.getDigest().getValue()));
                        LOG.warn("Computed : '{}'", computedDigest);
                    }
                }

            } else {
                LOG.warn("Digest is not defined for signed data with name '{}'", entry.getFileName());
            }

            if (!entry.isFound()) {
                LOG.warn("Signed data with name '{}' not found", entry.getFileName());
            }
        }

        return manifestEntries;
    }

}
