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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteListOfTrustedEntitiesSignatureParameters;

import java.io.Serializable;

/**
 * Service to be used for a simplified straight-forward signing of a List of Trusted Entities.
 * The class verifies the data format of the provided document and chooses the relevant handler to create the signature.
 * The following LoTE types are supported:
 * - ETSI TS 119 602 JSON List of Trusted Entities (creates compact JAdES-BASELINE-B signature as per ETSI TS 119 182-1);
 * - ETSI TS 119 602 XML List of Trusted Entities (creates enveloped XAdES-BASELINE-B signature as per ETSI EN 119 132-1);
 * - ISO/IEC 18013-5 VICAL (creates COSE_Sign1 CB-AdES-BASELINE-B signature as per ETSI TS 119 152-1).
 * <p>
 * NOTE: Unlike {@link RemoteTrustedListSignatureService} the class does not verify conformity of the submitted
 * document to the applicable schema definition, thus allowing signature of other document profiles which are
 * based on the ETSI TS 119 602
 *
 */
public interface RemoteListOfTrustedEntitiesSignatureService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed for a conformant List of Trusted Entities signing
     * according to a set of customizable parameters
     *
     * @param listOfTrustedEntities
     *            {@link RemoteDocument} List of Trusted Entities to be signed
     * @param parameters
     *            {@link RemoteListOfTrustedEntitiesSignatureParameters} set of the signing parameters
     *                                                         for Trusted List signature creation
     * @return the data to be signed
     */
    ToBeSignedDTO getDataToSign(final RemoteDocument listOfTrustedEntities, final RemoteListOfTrustedEntitiesSignatureParameters parameters);

    /**
     * Signs the List of Trusted Entities with the provided {@code signatureValue} according to a set of customizable parameters.
     * This method produces a signed List of Trusted Entities with an enveloped signature.
     *
     * @param listOfTrustedEntities
     *            {@link RemoteDocument} XML trusted list to be signed
     * @param parameters
     *            {@link RemoteListOfTrustedEntitiesSignatureParameters} set of the signing parameters
     * @param signatureValue
     *            {@link SignatureValueDTO} the signature value to incorporate
     * @return the signed List of Trusted Entities
     */
    RemoteDocument signDocument(final RemoteDocument listOfTrustedEntities, final RemoteListOfTrustedEntitiesSignatureParameters parameters,
                                final SignatureValueDTO signatureValue);

}
