package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.MultiValuesConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttestationSupportedNamespacesCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("org.iso.18013.5.1");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlClaim xmlClaim = new XmlClaim();
        xmlClaim.setText("John");
        xmlClaim.setName("given_name");
        xmlClaim.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setGivenName(xmlClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck asnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        asnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("org.iso.18013.5.1");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlClaim xmlClaim = new XmlClaim();
        xmlClaim.setText("John");
        xmlClaim.setName("given_name");
        xmlClaim.setNamespace("org.iso.23220.1");
        xmlAttestationPayload.setGivenName(xmlClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck asnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        asnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void additionalNamespaceTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("org.iso.18013.5.1");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlClaim xmlClaim = new XmlClaim();

        xmlClaim.setText("John");
        xmlClaim.setName("given_name");
        xmlClaim.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setGivenName(xmlClaim);

        XmlClaim additionalClaim = new XmlClaim();
        xmlClaim.setText("claim");
        additionalClaim.setName("additional");
        xmlClaim.setNamespace("org.iso.23220.1");
        xmlAttestationPayload.getOtherClaim().add(additionalClaim);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck asnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        asnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notPresentNamespaceTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("org.iso.18013.5.1");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck asnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        asnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
