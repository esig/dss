package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.QCIdentMethodEnum;
import eu.europa.esig.dss.policy.MultiValuesConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcIdentificationMethodCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateQcIdentificationMethodCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue(QCIdentMethodEnum.QCT_EIDAS2_B.getOid());
        xmlQcStatements.setQcIdentMethod(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(QCIdentMethodEnum.QCT_EIDAS2_B.getOid());

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcIdentificationMethodCheck cqcqscdlc = new CertificateQcIdentificationMethodCheck(
                i18nProvider, result, new CertificateWrapper(xc), new MultiValuesConstraintWrapper(constraint));
        cqcqscdlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue(QCIdentMethodEnum.QCT_EIDAS2_B.getOid());
        xmlQcStatements.setQcIdentMethod(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(QCIdentMethodEnum.QCT_EIDAS2_ACD.getOid());

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcIdentificationMethodCheck cqcqscdlc = new CertificateQcIdentificationMethodCheck(
                i18nProvider, result, new CertificateWrapper(xc), new MultiValuesConstraintWrapper(constraint));
        cqcqscdlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void multiValuesTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue(QCIdentMethodEnum.QCT_EIDAS2_B.getOid());
        xmlQcStatements.setQcIdentMethod(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(QCIdentMethodEnum.QCT_EIDAS2_B.getOid());
        constraint.getId().add(QCIdentMethodEnum.QCT_EIDAS2_ACD.getOid());

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcIdentificationMethodCheck cqcqscdlc = new CertificateQcIdentificationMethodCheck(
                i18nProvider, result, new CertificateWrapper(xc), new MultiValuesConstraintWrapper(constraint));
        cqcqscdlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notDefinedTest() {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(QCIdentMethodEnum.QCT_EIDAS2_B.getOid());

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcIdentificationMethodCheck cqcqscdlc = new CertificateQcIdentificationMethodCheck(
                i18nProvider, result, new CertificateWrapper(xc), new MultiValuesConstraintWrapper(constraint));
        cqcqscdlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noQcStatementsTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(QCIdentMethodEnum.QCT_EIDAS2_B.getOid());

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcIdentificationMethodCheck cqcqscdlc = new CertificateQcIdentificationMethodCheck(
                i18nProvider, result, new CertificateWrapper(xc), new MultiValuesConstraintWrapper(constraint));
        cqcqscdlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
