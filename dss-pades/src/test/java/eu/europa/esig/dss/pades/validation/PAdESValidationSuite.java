package eu.europa.esig.dss.pades.validation;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses(value = { ASN1Policy.class, DSS1188.class, DSS1376GetOriginalDoc.class, DSS1420.class, DSS818.class, DSS917.class, PadesWrongDigestAlgo.class,
		PdfPkcs7.class,
		DSS1443.class, DSS1444.class })
public class PAdESValidationSuite {

}
