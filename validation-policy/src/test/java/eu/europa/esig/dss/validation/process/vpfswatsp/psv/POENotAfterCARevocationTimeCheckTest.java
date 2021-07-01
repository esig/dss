package eu.europa.esig.dss.validation.process.vpfswatsp.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POENotAfterCARevocationTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class POENotAfterCARevocationTimeCheckTest extends AbstractTestCheck {

    private static final String REVOC_ONE_ID = "R-1";
    private static final String REVOC_TWO_ID = "R-2";

    @Test
    public void validCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        XmlTimestampedObject xmlTimestampedObjectTwo = new XmlTimestampedObject();
        xmlTimestampedObjectTwo.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectTwo.setToken(xmlRevocationTwo);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectTwo);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationOne), new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void onlyOneRevocPOECheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationOne), new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void anotherRevocPoeCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTstTimeCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() + 86400000)); // 24 hours after

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        XmlTimestampedObject xmlTimestampedObjectTwo = new XmlTimestampedObject();
        xmlTimestampedObjectTwo.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectTwo.setToken(xmlRevocationTwo);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectTwo);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationOne), new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
