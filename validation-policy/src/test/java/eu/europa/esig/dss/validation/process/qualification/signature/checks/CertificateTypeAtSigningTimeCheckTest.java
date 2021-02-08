package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateTypeAtSigningTimeCheckTest extends AbstractTestCheck {

    @Test
    public void qCertForESigTest() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationSignatureQualification result = new XmlValidationSignatureQualification();
        CertificateTypeAtSigningTimeCheck ctstc = new CertificateTypeAtSigningTimeCheck(i18nProvider, result,
                CertificateQualification.QCERT_FOR_ESIG, constraint);
        ctstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void certForESealTest() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationSignatureQualification result = new XmlValidationSignatureQualification();
        CertificateTypeAtSigningTimeCheck ctstc = new CertificateTypeAtSigningTimeCheck(i18nProvider, result,
                CertificateQualification.CERT_FOR_ESEAL, constraint);
        ctstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void naTest() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationSignatureQualification result = new XmlValidationSignatureQualification();
        CertificateTypeAtSigningTimeCheck ctstc = new CertificateTypeAtSigningTimeCheck(i18nProvider, result,
                CertificateQualification.NA, constraint);
        ctstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
