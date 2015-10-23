package eu.europa.esig.dss.applet;

import java.applet.Applet;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;

@SuppressWarnings("serial")
public class AppletLoader extends Applet {

	private static final Logger logger = LoggerFactory.getLogger(AppletLoader.class);

	private static final String PARAMETER_OPERATION = "operation";
	private static final String PARAMETER_TOKEN = "token";

	private static final String PARAMETER_DIGEST_TO_SIGN = "base64Digest";
	private static final String PARAMETER_DIGET_ALGORITHM = "digestAlgo";
	private static final String PARAMETER_BASE64_CERTIFICATE = "base64Certificate";

	private static final String PARAMETER_PKCS11_PATH = "pkcs11LibPath";
	private static final String PARAMETER_PKCS11_PWD = "pkcs11Pwd";

	private SignatureTokenType tokenType;
	private Operation operation;

	private String base64Certificate;
	private ToBeSigned toBeSigned;
	private DigestAlgorithm digestAlgorithm;

	private String pkcs11LibPath;
	private char[] pkcs11Pwd;

	@Override
	public void init() {
		super.init();
		initParameters();
		logger.info("Applet is correctly initialized with " + PARAMETER_OPERATION + "=" + operation + " and " + PARAMETER_TOKEN + "=" + tokenType);

		JSInvoker jsInvoker = new JSInvoker(this);

		SignatureTokenConnection tokenConnection = null;

		try {
			switch (tokenType) {
				case MSCAPI:
					tokenConnection = new MSCAPISignatureToken();
					break;
				case PKCS11:
					tokenConnection = new Pkcs11SignatureToken(pkcs11LibPath, pkcs11Pwd);
					break;
				default:
					logger.error("Unsupported token type : " + tokenType);
					return;
			}
		} catch (Exception e) {
			logger.error("Cannot initialize the token : " + e.getMessage(), e);
			return;
		}

		switch (operation) {
			case load_certificates:
				CertificateRetriever certificateRetriever = new CertificateRetriever(tokenConnection, jsInvoker);
				certificateRetriever.injectCertificates();
				break;
			case sign_digest:
				DigestSigner digestSigner = new DigestSigner(tokenConnection, toBeSigned, digestAlgorithm, base64Certificate, jsInvoker);
				digestSigner.signAndInject();
				break;
			default:
				logger.error("Unsupported operation : " + operation);
				return;
		}

	}

	/**
	 * This method load required parameters
	 */
	private void initParameters() {
		String parameterOperation = getParameter(PARAMETER_OPERATION);
		if (parameterOperation != null) {
			operation = Operation.valueOf(parameterOperation);
		}

		String parameterToken = getParameter(PARAMETER_TOKEN);
		if (parameterToken != null) {
			tokenType = SignatureTokenType.valueOf(parameterToken);
		}

		if (operation == null) {
			throw new RuntimeException("Unable to retrieve '" + PARAMETER_OPERATION + "' parameter (" + parameterOperation + ")");
		}

		if (tokenType == null) {
			throw new RuntimeException("Unable to retrieve  '" + PARAMETER_TOKEN + "' parameter (" + parameterToken + ")");
		}

		if (Operation.sign_digest.equals(operation)) {
			String parameterDigest = getParameter(PARAMETER_DIGEST_TO_SIGN);
			if (parameterDigest != null) {
				toBeSigned = new ToBeSigned(DatatypeConverter.parseBase64Binary(parameterDigest));
			}

			String parameterAlgo = getParameter(PARAMETER_DIGET_ALGORITHM);
			if (parameterAlgo != null) {
				digestAlgorithm = DigestAlgorithm.valueOf(parameterAlgo);
			}

			base64Certificate = getParameter(PARAMETER_BASE64_CERTIFICATE);
		}

		if (SignatureTokenType.PKCS11.equals(tokenType)) {
			pkcs11LibPath = getParameter(PARAMETER_PKCS11_PATH);
			pkcs11Pwd = getParameter(PARAMETER_PKCS11_PWD).toCharArray();
		}
	}

}
