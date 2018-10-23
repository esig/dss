package eu.europa.esig.dss.cades.signature;

import org.bouncycastle.cms.CMSException;
import org.junit.Test;

import eu.europa.esig.dss.cades.validation.CAdESSignature;

public class CAdESSignatureTest {

	@Test(expected = NullPointerException.class)
	public void initNull() throws CMSException {
		new CAdESSignature(null);
	}

	@Test(expected = CMSException.class)
	public void initEmptyByteArray() throws CMSException {
		new CAdESSignature(new byte[] {});
	}

}
