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
package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * Represents a DataTransferObject containing the required parameters for creation of DTBS (Data To Be Signed)
 * to be used for CMS for PAdES signature creation.
 * <p>
 * It's only possible to transfer an object by POST and REST.
 *
 */
public class DataToSignExternalCmsDTO extends AbstractDataToSignDTO {

    private static final long serialVersionUID = -442105442755635331L;

    /** Message-digest computed in PDF signature ByteRange */
    private DigestDTO messageDigest;

    /**
     * Empty constructor
     */
    public DataToSignExternalCmsDTO() {
        super();
    }

    /**
     * Default constructor
     *
     * @param messageDigest {@link DigestDTO} containing message-digest computed on PDF signature revision ByteRange
     * @param parameters {@link RemoteSignatureParameters} set of driven signature creation parameters
     */
    public DataToSignExternalCmsDTO(DigestDTO messageDigest, RemoteSignatureParameters parameters) {
        super(parameters);
        this.messageDigest = messageDigest;
    }

    /**
     * Gets the message-digest
     *
     * @return {@link DigestDTO}
     */
    public DigestDTO getMessageDigest() {
        return messageDigest;
    }

    /**
     * Sets the message-digest
     *
     * @param messageDigest {@link DigestDTO}
     */
    public void setMessageDigest(DigestDTO messageDigest) {
        this.messageDigest = messageDigest;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (messageDigest != null ? messageDigest.hashCode() : 0);
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DataToSignExternalCmsDTO)) return false;
        if (!super.equals(o)) return false;
        DataToSignExternalCmsDTO that = (DataToSignExternalCmsDTO) o;
        return Objects.equals(messageDigest, that.messageDigest);
    }

    @Override
    public String toString() {
        return "DataToSignExternalCMSDTO [messageDigest=" + messageDigest + ", parameters=" + getParameters() + "]";
    }

}
