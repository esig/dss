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
package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * Represents a DataTransferObject containing the required parameters for creation of a CMS signature (CMSSignedData)
 * suitable for PAdES signing (to be enveloped within PDF signature revision).
 * <p>
 * It's only possible to transfer an object by POST and REST.
 *
 */
public class SignMessageDigestExternalCmsDTO extends AbstractSignDocumentDTO {

    private static final long serialVersionUID = -4212141706198393826L;

    /** Message-digest computed in PDF signature ByteRange */
    private DigestDTO messageDigest;

    /**
     * Empty constructor
     */
    public SignMessageDigestExternalCmsDTO() {
        super();
    }

    /**
     * Default constructor
     *
     * @param messageDigest {@link DigestDTO} digest computed on prepared PDF signature revision
     * @param parameters {@link RemoteSignatureParameters} set of signature-driving parameters
     * @param signatureValue {@link SignatureValueDTO} contains result of a private-key encryption of a DTBS
     */
    public SignMessageDigestExternalCmsDTO(DigestDTO messageDigest, RemoteSignatureParameters parameters,
                                           SignatureValueDTO signatureValue) {
        super(parameters, signatureValue);
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SignMessageDigestExternalCmsDTO)) return false;
        if (!super.equals(o)) return false;
        SignMessageDigestExternalCmsDTO that = (SignMessageDigestExternalCmsDTO) o;
        return Objects.equals(messageDigest, that.messageDigest);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), messageDigest);
    }

    @Override
    public String toString() {
        return "SignMessageDigestExternalCMSDTO [messageDigest=" + messageDigest + ", parameters=" + getParameters() +
                ", signatureValue=" + getSignatureValue() + "]";
    }

}
