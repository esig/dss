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
package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.eaa.AttestationValidationParameters;

/**
 * Contains supplementary data parameters for validation of Mdoc EAA presentation
 *
 */
public class MdocValidationParameters implements AttestationValidationParameters {

    private static final long serialVersionUID = 8075475063597375229L;

    /** Contains transcript of communication used for the device retrieval (mdoc key binding signature) */
    private DSSDocument sessionTranscript;

    /**
     * Default constructor
     */
    public MdocValidationParameters() {
        // empty
    }

    /**
     * Gets the session transcript of communication used for the device retrieval (mdoc key binding signature)
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getSessionTranscript() {
        return sessionTranscript;
    }

    /**
     * Sets the session transcript of communication used for the device retrieval (mdoc key binding signature)
     *
     * @param sessionTranscript {@link DSSDocument}
     */
    public void setSessionTranscript(DSSDocument sessionTranscript) {
        this.sessionTranscript = sessionTranscript;
    }

}
