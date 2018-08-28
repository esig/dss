package eu.europa.esig.dss.pades.validation;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses(value = { DSS1188.class, DSS1376GetOriginalDoc.class, DSS1420.class, DSS818.class, DSS917.class, PadesWrongDigestAlgo.class, PdfPkcs7.class })
public class PAdESValidationSuite {

}
