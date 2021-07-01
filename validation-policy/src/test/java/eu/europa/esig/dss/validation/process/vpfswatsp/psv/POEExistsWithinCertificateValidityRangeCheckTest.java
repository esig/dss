package eu.europa.esig.dss.validation.process.vpfswatsp.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
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
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POEExistsWithinCertificateValidityRangeCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class POEExistsWithinCertificateValidityRangeCheckTest extends AbstractTestCheck {

    private static final String CERT_ID = "C-1";

    @Test
    public void validCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date currentTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);
        xmlCertificate.setNotBefore(new Date(currentTime.getTime() - 86400000)); // 24 hours ago
        xmlCertificate.setNotAfter(new Date(currentTime.getTime() + 86400000)); // 24 hours after

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(currentTime);

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

        XmlPSV result = new XmlPSV();
        POEExistsWithinCertificateValidityRangeCheck pecvrc = new POEExistsWithinCertificateValidityRangeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), poeExtraction, constraint);
        pecvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTstCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date currentTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);
        xmlCertificate.setNotBefore(new Date(currentTime.getTime() - 86400000)); // 24 hours ago
        xmlCertificate.setNotAfter(new Date(currentTime.getTime() + 86400000)); // 24 hours after

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(currentTime);

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

        XmlPSV result = new XmlPSV();
        POEExistsWithinCertificateValidityRangeCheck pecvrc = new POEExistsWithinCertificateValidityRangeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), poeExtraction, constraint);
        pecvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidRangeCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date currentTime = new Date();

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(CERT_ID);
        xmlCertificate.setNotBefore(new Date(currentTime.getTime() - 172800000)); // 48 hours ago
        xmlCertificate.setNotAfter(new Date(currentTime.getTime() - 86400000)); // 24 hours ago

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(currentTime);

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

        XmlPSV result = new XmlPSV();
        POEExistsWithinCertificateValidityRangeCheck pecvrc = new POEExistsWithinCertificateValidityRangeCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), poeExtraction, constraint);
        pecvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
