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
package eu.europa.esig.dss.ws.attestation.validation.common;

import eu.europa.esig.dss.attestation.mdoc.validation.MdocValidationParameters;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

/**
 * Builds EAA validation parameters for Mdoc validation
 *
 */
public class RemoteMdocValidationParametersBuilder {

    /** Document containing SessionTranscript structure */
    private RemoteDocument sessionTranscript;

    /**
     * Default constructor
     */
    public RemoteMdocValidationParametersBuilder() {
        // empty
    }

    /**
     * Sets SessionTranscript
     *
     * @param sessionTranscript {@link RemoteDocument}
     * @return this {@link RemoteMdocValidationParametersBuilder}
     */
    public RemoteMdocValidationParametersBuilder setSessionTranscript(RemoteDocument sessionTranscript) {
        this.sessionTranscript = sessionTranscript;
        return this;
    }

    /**
     * Builds the MdocValidationParameters
     *
     * @return {@link MdocValidationParameters}
     */
    public MdocValidationParameters build() {
        final MdocValidationParameters mdocValidationParameters = new MdocValidationParameters();
        if (sessionTranscript != null) {
            mdocValidationParameters.setSessionTranscript(RemoteDocumentConverter.toDSSDocument(sessionTranscript));
        }
        return mdocValidationParameters;
    }

}
