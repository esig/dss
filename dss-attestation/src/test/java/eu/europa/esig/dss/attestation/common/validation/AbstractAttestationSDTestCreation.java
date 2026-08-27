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

import eu.europa.esig.dss.attestation.common.creation.AttestationPayloadParameters;
import eu.europa.esig.dss.attestation.common.creation.AttestationSDService;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class AbstractAttestationSDTestCreation<SP extends SerializableSignatureParameters, B extends AttestationPayloadParameters,
        D extends SelectiveDisclosure> extends AbstractAttestationTestCreation<SP, B> {

    @Override
    protected abstract AttestationSDService<SP, B, D> getService();

    protected List<D> getDisclosures() {
        B payloadParameters = getPayloadParameters();
        AttestationSDService<SP, B, D> service = getService();
        return service.generateDisclosures(payloadParameters);
    }

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument signedAttestation = super.getSignedDocument();
        AttestationSDService<SP, B, D> service = getService();
        return service.issueAttestation(signedAttestation, getDisclosures());
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());

        List<D> disclosures = getDisclosures();
        assertEquals(disclosures.size(), attestation.getDigestMatchers().stream().filter(
                d-> DigestMatcherType.SELECTIVE_DISCLOSURE == d.getType()).count());
        assertEquals(getNumberOfOrphanSDClaims(), attestation.getDigestMatchers().stream().filter(
                d-> DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == d.getType()).count());
    }

}
