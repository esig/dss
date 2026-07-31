package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationPayloadProxy;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.attestation.mdoc.ISO180135Headers;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocISOMdLInvalidDrivingPrivilegeTest extends AbstractMdocIssuerSignedTestCreation {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO18013_5_MDL_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        MdocClaimArray drivingPrivileges = MdocClaim.createArray(MdocConstants.ISO18013_5_NAMESPACE, ISO180135Headers.DRIVING_PRIVILEGES);

        MdocClaimObject drivingPrivilegeValid = MdocClaim.createObject();
        drivingPrivilegeValid.addChild(MdocClaim.create(ISO180135Headers.DRIVING_PRIVILEGES_VEHICLE_CATEGORY_CODE, "B"));
        drivingPrivilegeValid.addChild(MdocClaim.create(ISO180135Headers.DRIVING_PRIVILEGES_ISSUE_DATE, DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1)));
        drivingPrivilegeValid.addChild(MdocClaim.create(ISO180135Headers.DRIVING_PRIVILEGES_EXPIRY_DATE, DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1)));
        drivingPrivileges.addElement(drivingPrivilegeValid);

        drivingPrivileges.addElement(MdocClaim.create("A"));

        payloadParameters.selectivelyDisclosable().addClaim(drivingPrivileges);

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        AttestationPayloadProxy attestationPayload = attestation.getPayload();

        DrivingPrivilegesClaimWrapper drivingPrivilegesClaimWrapper = attestationPayload.getDrivingPrivileges();
        assertNotNull(drivingPrivilegesClaimWrapper);

        List<DrivingPrivilegeClaimWrapper> drivingPrivileges = drivingPrivilegesClaimWrapper.getDrivingPrivileges();
        assertEquals(1, drivingPrivileges.size());
        assertEquals("B", drivingPrivileges.get(0).getVehicleCategoryCode().getText());

        List<ClaimWrapper> list = drivingPrivilegesClaimWrapper.getList();
        assertEquals(2, list.size());

        boolean aFound = false;
        boolean bFound = false;
        for (ClaimWrapper claimWrapper : list) {
            if ("A".equals(claimWrapper.getText())) {
                aFound = true;
            } else if ("B".equals(claimWrapper.getMap().get("vehicle_category_code").getText())) {
                bFound = true;
            }
        }
        assertTrue(aFound);
        assertTrue(bFound);
    }

    @Override
    protected void assertDrivingPrivilegesEquals(List<MdocDrivingPrivilege> drivingPrivileges, DrivingPrivilegesClaimWrapper drivingPrivilegesClaimWrapper) {
        // skip
    }

    @Override
    protected MdocPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
