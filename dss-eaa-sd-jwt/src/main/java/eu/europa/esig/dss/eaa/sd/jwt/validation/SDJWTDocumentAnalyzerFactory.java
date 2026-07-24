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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.eaa.common.validation.DefaultAttestationDocumentAnalyzer;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.eaa.AttestationDocumentAnalyzerFactory;

/**
 * This class is used to load a corresponding {@code eu.europa.esig.dss.spi.validation.analyzer.eaa.EAAPresentationAnalyzer}
 * for an SD-JWT VC validation
 *
 */
public class SDJWTDocumentAnalyzerFactory implements AttestationDocumentAnalyzerFactory {

    /**
     * Default constructor
     */
    public SDJWTDocumentAnalyzerFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        SDJWTCompactAttestationDocumentAnalyzer compactAnalyzer = new SDJWTCompactAttestationDocumentAnalyzer();
        if (compactAnalyzer.isSupported(document)) {
            return true;
        }

        SDJWTJsonSerializationAttestationDocumentAnalyzer jsonSerializationAnalyzer = new SDJWTJsonSerializationAttestationDocumentAnalyzer();
        if (jsonSerializationAnalyzer.isSupported(document)) {
            return true;
        }

        return false;
    }

    @Override
    public DefaultAttestationDocumentAnalyzer create(DSSDocument document) {
        SDJWTCompactAttestationDocumentAnalyzer compactAnalyzer = new SDJWTCompactAttestationDocumentAnalyzer();
        if (compactAnalyzer.isSupported(document)) {
            return new SDJWTCompactAttestationDocumentAnalyzer(document);
        }

        SDJWTJsonSerializationAttestationDocumentAnalyzer jsonSerializationAnalyzer = new SDJWTJsonSerializationAttestationDocumentAnalyzer();
        if (jsonSerializationAnalyzer.isSupported(document)) {
            return new SDJWTJsonSerializationAttestationDocumentAnalyzer(document);
        }

        throw new IllegalArgumentException("Not supported document");
    }

}
