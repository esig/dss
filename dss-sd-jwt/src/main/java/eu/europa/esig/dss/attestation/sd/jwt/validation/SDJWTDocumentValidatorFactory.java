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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.attestation.common.validation.AttestationDocumentValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to load a relevant validator for a presentation of attestation validation
 *
 */
public class SDJWTDocumentValidatorFactory implements AttestationDocumentValidatorFactory {

    /**
     * Default constructor
     */
    public SDJWTDocumentValidatorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        SDJWTCompactDocumentValidator compactValidator = new SDJWTCompactDocumentValidator();
        if (compactValidator.isSupported(document)) {
            return true;
        }

        SDJWTJsonSerializationDocumentValidator jsonSerializationValidator = new SDJWTJsonSerializationDocumentValidator();
        if (jsonSerializationValidator.isSupported(document)) {
            return true;
        }

        return false;
    }

    @Override
    public AbstractSDJWTDocumentValidator create(DSSDocument document) {
        SDJWTCompactDocumentValidator compactValidator = new SDJWTCompactDocumentValidator();
        if (compactValidator.isSupported(document)) {
            return new SDJWTCompactDocumentValidator(document);
        }

        SDJWTJsonSerializationDocumentValidator jsonSerializationValidator = new SDJWTJsonSerializationDocumentValidator();
        if (jsonSerializationValidator.isSupported(document)) {
            return new SDJWTJsonSerializationDocumentValidator(document);
        }

        throw new IllegalArgumentException("Not supported document");
    }

}