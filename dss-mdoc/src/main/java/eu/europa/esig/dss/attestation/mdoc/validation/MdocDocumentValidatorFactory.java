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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.attestation.common.validation.AttestationDocumentValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Processes and validated Electronic Attestation of Attributes (EAAs) provided within an mdoc document structure
 * as per ISO 18013-5.
 *
 */
public class MdocDocumentValidatorFactory implements AttestationDocumentValidatorFactory {

    /**
     * Default constructor
     */
    public MdocDocumentValidatorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        MdocDeviceResponseAttestationDocumentValidator mdocDeviceResponseValidator = new MdocDeviceResponseAttestationDocumentValidator();
        if (mdocDeviceResponseValidator.isSupported(document)) {
            return true;
        }

        MdocIssuerSignedAttestationDocumentValidator mdocIssuerSignedValidator = new MdocIssuerSignedAttestationDocumentValidator();
        if (mdocIssuerSignedValidator.isSupported(document)) {
            return true;
        }

        return false;
    }

    @Override
    public DefaultAttestationDocumentValidator create(DSSDocument document) {
        MdocDeviceResponseAttestationDocumentValidator mdocDeviceResponseValidator = new MdocDeviceResponseAttestationDocumentValidator();
        if (mdocDeviceResponseValidator.isSupported(document)) {
            return new MdocDeviceResponseAttestationDocumentValidator(document);
        }

        MdocIssuerSignedAttestationDocumentValidator mdocIssuerSignedValidator = new MdocIssuerSignedAttestationDocumentValidator();
        if (mdocIssuerSignedValidator.isSupported(document)) {
            return new MdocIssuerSignedAttestationDocumentValidator(document);
        }

        throw new IllegalArgumentException("Not supported document");
    }

}
