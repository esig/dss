package eu.europa.esig.dss.validation.process.vpfswatsp.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.POEExistsAtOrBeforeControlTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class POEExistsAtOrBeforeControlTimeCheckTest extends AbstractTestCheck {

    private static final String CERT_ID = "C-1";

    @Test
    public void validCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date controlTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(controlTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setCategory(TimestampedObjectType.CERTIFICATE);
        xmlTimestampedObject.setToken(xmlCertificate);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObject);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlVTS result = new XmlVTS();
        POEExistsAtOrBeforeControlTimeCheck peabctc = new POEExistsAtOrBeforeControlTimeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), TimestampedObjectType.CERTIFICATE, controlTime, poeExtraction, constraint);
        peabctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void porAtControlTimeCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date controlTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(controlTime);

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setCategory(TimestampedObjectType.CERTIFICATE);
        xmlTimestampedObject.setToken(xmlCertificate);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObject);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlVTS result = new XmlVTS();
        POEExistsAtOrBeforeControlTimeCheck peabctc = new POEExistsAtOrBeforeControlTimeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), TimestampedObjectType.CERTIFICATE, controlTime, poeExtraction, constraint);
        peabctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void poeAfterCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date controlTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(controlTime.getTime() + 86400000)); // 24 hours after

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setCategory(TimestampedObjectType.CERTIFICATE);
        xmlTimestampedObject.setToken(xmlCertificate);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObject);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlVTS result = new XmlVTS();
        POEExistsAtOrBeforeControlTimeCheck peabctc = new POEExistsAtOrBeforeControlTimeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), TimestampedObjectType.CERTIFICATE, controlTime, poeExtraction, constraint);
        peabctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void noPoeCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date controlTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(controlTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setCategory(TimestampedObjectType.CERTIFICATE);
        xmlTimestampedObject.setToken(new XmlCertificate());
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObject);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlVTS result = new XmlVTS();
        POEExistsAtOrBeforeControlTimeCheck peabctc = new POEExistsAtOrBeforeControlTimeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), TimestampedObjectType.CERTIFICATE, controlTime, poeExtraction, constraint);
        peabctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTstCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date controlTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(controlTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(false);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setCategory(TimestampedObjectType.CERTIFICATE);
        xmlTimestampedObject.setToken(xmlCertificate);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObject);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlVTS result = new XmlVTS();
        POEExistsAtOrBeforeControlTimeCheck peabctc = new POEExistsAtOrBeforeControlTimeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), TimestampedObjectType.CERTIFICATE, controlTime, poeExtraction, constraint);
        peabctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
