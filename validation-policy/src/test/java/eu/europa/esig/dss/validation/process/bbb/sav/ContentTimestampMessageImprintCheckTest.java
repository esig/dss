package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTimestampMessageImprintCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ContentTimestampMessageImprintCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
        digestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        digestMatcher.setDataFound(true);
        digestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(digestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ContentTimestampMessageImprintCheck ctmic = new ContentTimestampMessageImprintCheck(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), constraint);
        ctmic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void failedTest() throws Exception {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
        digestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        digestMatcher.setDataFound(true);
        digestMatcher.setDataIntact(false);
        xmlTimestamp.getDigestMatchers().add(digestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ContentTimestampMessageImprintCheck ctmic = new ContentTimestampMessageImprintCheck(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), constraint);
        ctmic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }
    
}
