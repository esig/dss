package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateTypeCheckTest extends AbstractTestCheck {

    @Test
    public void eSignTest() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationCertificateQualification result = new XmlValidationCertificateQualification();
        CertificateTypeCheck ctc = new CertificateTypeCheck(i18nProvider, result, CertificateType.ESIGN,
                ValidationTime.CERTIFICATE_ISSUANCE_TIME, constraint);
        ctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void eSealTest() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationCertificateQualification result = new XmlValidationCertificateQualification();
        CertificateTypeCheck ctc = new CertificateTypeCheck(i18nProvider, result, CertificateType.ESEAL,
                ValidationTime.VALIDATION_TIME, constraint);
        ctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void wsaTest() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationCertificateQualification result = new XmlValidationCertificateQualification();
        CertificateTypeCheck ctc = new CertificateTypeCheck(i18nProvider, result, CertificateType.WSA,
                ValidationTime.BEST_SIGNATURE_TIME, constraint);
        ctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void unknownTypeTest() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationCertificateQualification result = new XmlValidationCertificateQualification();
        CertificateTypeCheck ctc = new CertificateTypeCheck(i18nProvider, result, CertificateType.UNKNOWN,
                ValidationTime.BEST_SIGNATURE_TIME, constraint);
        ctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
