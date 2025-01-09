package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLStructureCheckTest extends AbstractTestCheck {

    @Test
    void validCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(true);
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, constraint);
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(false);
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, constraint);
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validWithMessageCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(true);
        xmlStructuralValidation.getMessages().add("Valid structure");
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, constraint);
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidWithMessageCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(false);
        xmlStructuralValidation.getMessages().add("Error message");
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, constraint);
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void nullCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, constraint);
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noStructureValidationCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, constraint);
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
