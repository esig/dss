package eu.europa.esig.dss.pades.timestamp;

import eu.europa.esig.dss.pades.timestamp.suite.PAdESTimestampSignedPdfTest;
import eu.europa.esig.dss.pades.timestamp.suite.PAdESTimestampTest;
import eu.europa.esig.dss.pades.timestamp.suite.PAdESTripleTimestampTest;
import eu.europa.esig.dss.pades.timestamp.suite.PDFTimestampServiceTest;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectClasses({ PDFTimestampServiceTest.class, PAdESTimestampTest.class, PAdESTripleTimestampTest.class,
        PAdESTimestampSignedPdfTest.class })
public class ITextPAdESTimestampSuiteTest {
}
