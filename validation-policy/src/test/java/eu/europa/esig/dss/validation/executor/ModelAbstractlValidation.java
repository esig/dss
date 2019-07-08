package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.jaxb.policy.Model;

/**
 * Implements basic test class for the model based certificate and signature
 * validations.
 *
 * @author akoepe
 * @version 1.0
 */
public class ModelAbstractlValidation {

	private static final Logger LOG = LoggerFactory.getLogger(ModelAbstractlValidation.class);

	/**
	 * Defines the list of involved diagnostic data, policy and their associated
	 * main signature key.
	 *
	 * @author akoepe
	 * @version 1.0
	 */
	public enum TestData {
		DATA_1("src/test/resources/diag_data_model_policy.xml", "src/test/resources/diag_data_model_1.xml",
				"C-3967083A1B9CE00484905529E22C64BBF622EE356088D62371B8069A84FE47F7", 2),
		DATA_2("src/test/resources/diag_data_model_policy.xml", "src/test/resources/diag_data_model_2.xml",
				"C-C01FC833D83EAF08F4031A1915A72BE6602A63587C5B65227D37461E35019532", 3),
		DATA_3("src/test/resources/diag_data_model_policy.xml", "src/test/resources/diag_data_model_3.xml", 
				"C-10065BCA3329FF0813FF6254448C6C9281F36C0630C71E9446F109FC1B5CDBCF", 4);

		private final String policy;
		private final String diagData;
		private final String certId;
		private final int countedCerts;

		/**
		 * Constructor.
		 * 
		 * @param policy
		 *            the policy file
		 * @param diagData
		 *            the diagnostic data file
		 * @param certId
		 *            the signature certificate identifier
		 * @param countedCerts
		 *            the expected length of the certificates chain
		 */
		TestData(final String policy, final String diagData, final String certId, final int countedCerts) {
			this.policy = policy;
			this.diagData = diagData;
			this.certId = certId;
			this.countedCerts = countedCerts;
		}

		public String getPolicy() {
			return policy;
		}

		public String getDiagnosticData() {
			return diagData;
		}

		public String getSignerCertificateIdentifier() {
			return certId;
		}

		public int getNumberOfInvolvedCertificates() {
			return countedCerts;
		}
	}

	/**
	 * Implements internal helper class that defines a given test case for the
	 * current JUnit implementation.
	 * 
	 * @author akoepe
	 * @version 1.0
	 */
	public static class TestCase {
		private final TestData testData;
		private final Model model;
		private final Date validationDate;
		private final CertificateQualification qualification;
		private final Map<String, Object> certResults;

		/**
		 * Constructor.
		 *
		 * @param testData
		 *            the test data to be used
		 * @param model
		 *            the validation model to be used
		 * @param validationDate
		 *            the validation date to be used
		 * @param qualification
		 *            the expected qualification
		 * @param expectedCertResults
		 *            the expected Indication per involved certificate
		 */
		protected TestCase(final TestData testData, final Model model, final Date validationDate,
				CertificateQualification qualification, final String... expectedCertResults) {
			this.testData = testData;
			this.model = model;
			this.validationDate = validationDate;
			this.qualification = qualification;

			certResults = new HashMap<>();
			for (String str : expectedCertResults) {
				String[] items = str.split(":");
				if (items.length > 1 && !items[1].isEmpty()) {
					certResults.put(items[0], getValue(items[0], items[1]));
				}
			}
		}

		public final TestData getTestData() {
			return testData;
		}

		public final Date getValidationDate() {
			return validationDate;
		}

		public final Model getModel() {
			return model;
		}

		public final CertificateQualification getQualification() {
			return qualification;
		}

		public final Object getExpectedCertResult(final String certId) {
			String str = certId;
			if (str.length() > 4) {
				str = str.substring(str.length() - 4);
			}
			return certResults.get(str);
		}

		private Object getValue(final String item, final String value) {
			if ("ind".equals(item) || (item.length() == 4 && item.matches("[0-9A-Z]+"))) {
				return Indication.valueOf(value);
			} else if ("sub".equals(item)) {
				return SubIndication.valueOf(value);
			}

			return "";
		}
	}
}
