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
