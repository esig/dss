package eu.europa.esig.dss.xades.validation;

import org.apache.xml.security.algorithms.implementations.SignatureBaseRSA;
import org.apache.xml.security.signature.XMLSignatureException;

/**
 * Support for RSA-PSS with SHA3
 * 
 * See https://tools.ietf.org/html/rfc6931
 */
public class SignatureRSAwithSHA3andMGF1Support {

	public static class SignatureRSASHA3224MGF1 extends SignatureBaseRSA {

		public static final String XML_ID = "http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1";

		public SignatureRSASHA3224MGF1() throws XMLSignatureException {
			super();
		}

		@Override
		public String engineGetURI() {
			return XML_ID;
		}

	}

	public static class SignatureRSASHA3256MGF1 extends SignatureBaseRSA {

		public static final String XML_ID = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";

		public SignatureRSASHA3256MGF1() throws XMLSignatureException {
			super();
		}

		@Override
		public String engineGetURI() {
			return XML_ID;
		}

	}

	public static class SignatureRSASHA3384MGF1 extends SignatureBaseRSA {

		public static final String XML_ID = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";

		public SignatureRSASHA3384MGF1() throws XMLSignatureException {
			super();
		}

		@Override
		public String engineGetURI() {
			return XML_ID;
		}

	}

	public static class SignatureRSASHA3512MGF1 extends SignatureBaseRSA {

		public static final String XML_ID = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";

		public SignatureRSASHA3512MGF1() throws XMLSignatureException {
			super();
		}

		@Override
		public String engineGetURI() {
			return XML_ID;
		}

	}

}
