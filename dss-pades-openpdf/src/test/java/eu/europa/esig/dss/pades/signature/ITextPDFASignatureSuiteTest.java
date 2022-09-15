package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.pdfa.signature.suite.PDFAPAdESLevelBTest;
import eu.europa.esig.dss.pdfa.signature.suite.PDFAWithFontSubsetTest;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({ PDFAPAdESLevelBTest.class, PDFAWithFontSubsetTest.class })
public class ITextPDFASignatureSuiteTest {

}
