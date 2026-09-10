package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AttestationStructuralValidationCheckTest extends AbstractTestCheck {

    @Test
    void structuralValidationCheck() {
        XmlStructuralValidation xsv = new XmlStructuralValidation();
        xsv.setValid(true);

        XmlAttestation attestation = new XmlAttestation();
        attestation.setStructuralValidation(xsv);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        AttestationStructuralValidationCheck asvc = new AttestationStructuralValidationCheck(i18nProvider, result, new AttestationWrapper(attestation), new LevelConstraintWrapper(constraint));
        asvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void failedStructuralValidationCheck() {
        XmlStructuralValidation xsv = new XmlStructuralValidation();
        xsv.setValid(false);

        XmlAttestation attestation = new XmlAttestation();
        attestation.setStructuralValidation(xsv);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        AttestationStructuralValidationCheck asvc = new AttestationStructuralValidationCheck(i18nProvider, result, new AttestationWrapper(attestation), new LevelConstraintWrapper(constraint));
        asvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void emptyStructuralValidationCheck() {
        XmlAttestation attestation = new XmlAttestation();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        AttestationStructuralValidationCheck asvc = new AttestationStructuralValidationCheck(i18nProvider, result, new AttestationWrapper(attestation), new LevelConstraintWrapper(constraint));
        asvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
