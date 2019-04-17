package eu.europa.esig.dss;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Date;

public class SignatureIdentifier extends Identifier {
	
	private static final long serialVersionUID = -6700888325973167656L;

	public static SignatureIdentifier buildSignatureIdentifier(Date signingTime, TokenIdentifier tokenIdentifier) {
		return buildSignatureIdentifier(signingTime, tokenIdentifier, null);
	}

	public static SignatureIdentifier buildSignatureIdentifier(Date signingTime, TokenIdentifier tokenIdentifier, String customIdentifier) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (signingTime != null) {
				dos.writeLong(signingTime.getTime());
			}
			if (tokenIdentifier != null) {
				dos.writeChars(tokenIdentifier.asXmlId());
			}
			if (customIdentifier != null) {
				dos.writeChars(customIdentifier);
			}
			dos.flush();
			return new SignatureIdentifier(baos.toByteArray());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	SignatureIdentifier(byte[] bytes) {
		super(bytes);
	}

}
