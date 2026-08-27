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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.attestation.common.creation.AttestationDocument;
import eu.europa.esig.dss.attestation.common.creation.AttestationPayloadParameters;
import eu.europa.esig.dss.attestation.common.creation.AttestationPresentationService;
import eu.europa.esig.dss.attestation.common.creation.KeyBindingParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.test.pki.CertEntitySignatureTokenConnection;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;

import java.util.List;

public abstract class AbstractAttestationPresentationTestCreation<SP extends SerializableSignatureParameters, B extends AttestationPayloadParameters,
        D extends SelectiveDisclosure, E extends KeyBindingParameters> extends AbstractAttestationSDTestCreation<SP, B, D> {

    protected abstract E getKeyBindingParameters();

    protected abstract SP getKeyBindingSignatureParameters();

    protected AbstractSignatureTokenConnection getDeviceToken() {
        return new CertEntitySignatureTokenConnection(getCertEntity(getDeviceSigningAlias()));
    }

    protected String getDeviceSigningAlias() {
        return getSigningAlias();
    }

    protected abstract AttestationPresentationService<SP, D, E> getPresentationService();

    protected DSSDocument createKeyBindingSignature(AttestationDocument<D> attestationDocument) {
        SP params = getKeyBindingSignatureParameters();
        AttestationPresentationService<SP, D, E> presentationService = getPresentationService();

        DSSDocument signedAttestation = attestationDocument.getSignedAttestation();
        List<D> disclosures = attestationDocument.getSelectiveDisclosures();
        E keyBindingParameters = getKeyBindingParameters();

        ToBeSigned dataToSign = presentationService.getDataToSignForKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, params);
        SignatureValue signatureValue = getDeviceToken().sign(dataToSign, params.getSignatureAlgorithm(), getDeviceToken().getKeys().iterator().next());
        // TODO : add signature verification ?
        return presentationService.createKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, params, signatureValue);
    }

    @Override
    protected DSSDocument getSignedDocument() {
        AttestationDocument<D> attestationDocument = getAttestationDocument();
        DSSDocument keyBindingSignature = createKeyBindingSignature(attestationDocument);
        AttestationPresentationService<SP, D, E> presentationService = getPresentationService();
        return presentationService.issuePresentation(attestationDocument.getSignedAttestation(), getDisclosures(), keyBindingSignature);
    }

    protected AttestationDocument<D> getAttestationDocument() {
        DSSDocument attestation = super.getSignedDocument();
        AttestationPresentationService<SP, D, E> presentationService = getPresentationService();
        return presentationService.parseAttestation(attestation);
    }

}
