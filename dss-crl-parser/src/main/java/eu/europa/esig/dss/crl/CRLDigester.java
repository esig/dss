package eu.europa.esig.dss.crl;

import java.security.DigestInputStream;

import eu.europa.esig.dss.crl.handler.ToBeSignedEventHandler;

/**
 * This class is used to compute the TBS digest value
 */
public class CRLDigester implements ToBeSignedEventHandler {

	private DigestInputStream dis;

	public CRLDigester(DigestInputStream dis) {
		this.dis = dis;
		// disabled by default, the data to be digested is not in the beginning
		this.dis.on(false);
	}

	@Override
	public void beforeTbs() {
		dis.on(true);
	}

	@Override
	public void afterTbs() {
		dis.on(false);
	}

	public byte[] getDigest() {
		return dis.getMessageDigest().digest();
	}

}
