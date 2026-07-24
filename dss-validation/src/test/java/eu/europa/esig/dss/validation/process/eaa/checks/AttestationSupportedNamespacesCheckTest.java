package eu.europa.esig.dss.validation.process.eaa.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAA;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPayload;
import eu.europa.esig.dss.enumerations.AttestationFormat;
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

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlClaim xmlClaim = new XmlClaim();
        xmlClaim.setText("John");
        xmlClaim.setName("given_name");
        xmlClaim.setNamespace("org.iso.18013.5.1");
        xmlEAAPayload.setGivenName(xmlClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck eaasnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        eaasnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("org.iso.18013.5.1");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlClaim xmlClaim = new XmlClaim();
        xmlClaim.setText("John");
        xmlClaim.setName("given_name");
        xmlClaim.setNamespace("org.iso.23220.1");
        xmlEAAPayload.setGivenName(xmlClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck eaasnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        eaasnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void additionalNamespaceTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("org.iso.18013.5.1");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlClaim xmlClaim = new XmlClaim();

        xmlClaim.setText("John");
        xmlClaim.setName("given_name");
        xmlClaim.setNamespace("org.iso.18013.5.1");
        xmlEAAPayload.setGivenName(xmlClaim);

        XmlClaim additionalClaim = new XmlClaim();
        xmlClaim.setText("claim");
        additionalClaim.setName("additional");
        xmlClaim.setNamespace("org.iso.23220.1");
        xmlEAAPayload.getOtherClaim().add(additionalClaim);

        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck eaasnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        eaasnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notPresentNamespaceTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("org.iso.18013.5.1");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);

        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedNamespacesCheck eaasnc = new AttestationSupportedNamespacesCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        eaasnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
