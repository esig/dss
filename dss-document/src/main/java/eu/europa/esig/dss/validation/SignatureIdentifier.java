package eu.europa.esig.dss.validation;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Date;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.identifier.Identifier;
import eu.europa.esig.dss.identifier.TokenIdentifier;

public class SignatureIdentifier extends Identifier {
	
	private static final long serialVersionUID = -6700888325973167656L;

	public static SignatureIdentifier buildSignatureIdentifier(Date signingTime, TokenIdentifier tokenIdentifier) {
		return buildSignatureIdentifier(signingTime, tokenIdentifier, null);
	}
	
	public static SignatureIdentifier buildSignatureIdentifier(Date signingTime, TokenIdentifier tokenIdentifier, String customIdentifier) {
		return buildSignatureIdentifier(signingTime, tokenIdentifier, null, customIdentifier);
	}

	public static SignatureIdentifier buildSignatureIdentifier(Date signingTime, TokenIdentifier tokenIdentifier, 
			Integer customInteger, String... stringIdentifiers) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (signingTime != null) {
				dos.writeLong(signingTime.getTime());
			}
			if (tokenIdentifier != null) {
				dos.writeChars(tokenIdentifier.asXmlId());
			}
			if (customInteger != null) {
				dos.writeInt(customInteger);
			}
			if (stringIdentifiers != null) {
				for (String str : stringIdentifiers) {
					if (str != null) {
						dos.writeChars(str);
					}
				}
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
