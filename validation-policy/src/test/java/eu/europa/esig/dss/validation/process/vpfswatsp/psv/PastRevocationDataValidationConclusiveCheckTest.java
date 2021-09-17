package eu.europa.esig.dss.validation.process.vpfswatsp.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastRevocationDataValidationConclusiveCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PastRevocationDataValidationConclusiveCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.PASSED);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlPSV result = new XmlPSV();
        PastRevocationDataValidationConclusiveCheck prdvcc = new PastRevocationDataValidationConclusiveCheck(
                i18nProvider, result, xmlConclusion, constraint);
        prdvcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.INDETERMINATE);
        xmlConclusion.setSubIndication(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlPSV result = new XmlPSV();
        PastRevocationDataValidationConclusiveCheck prdvcc = new PastRevocationDataValidationConclusiveCheck(
                i18nProvider, result, xmlConclusion, constraint);
        prdvcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
