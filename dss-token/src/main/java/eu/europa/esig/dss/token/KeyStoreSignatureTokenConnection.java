package eu.europa.esig.dss.token;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;

import eu.europa.esig.dss.DSSException;

public class KeyStoreSignatureTokenConnection extends AbstractKeyStoreTokenConnection {

	private final KeyStore keyStore;
	private final ProtectionParameter password;

	public KeyStoreSignatureTokenConnection(byte[] ksBytes, String ksType, String ksPassword) {
		this(new ByteArrayInputStream(ksBytes), ksType, ksPassword);
	}

	public KeyStoreSignatureTokenConnection(String filepath, String ksType, String ksPassword) throws IOException {
		this(new File(filepath), ksType, ksPassword);
	}

	public KeyStoreSignatureTokenConnection(File ksFile, String ksType, String ksPassword) throws IOException {
		this(new FileInputStream(ksFile), ksType, ksPassword);
	}

	/**
	 * Construct a KeyStoreSignatureTokenConnection object.
	 * Please note that the keystore password will also be used to retrieve the private key.
	 * For each keystore entry (identifiable by alias) the same private key password will be used.
	 * 
	 * If you want to specify a separate private key password use the {@link #getKey(String, String)} method.
	 * 
	 * @param ksStream
	 * @param ksType
	 * @param ksPassword
	 */
	public KeyStoreSignatureTokenConnection(InputStream ksStream, String ksType, String ksPassword) {
		try {
			this.keyStore = KeyStore.getInstance(ksType);
			this.password = createProtectionParameter(ksPassword);
			this.keyStore.load(ksStream, ((PasswordProtection) password).getPassword());
		} catch (Exception e) {
			throw new DSSException(e);
		} finally {
			if (ksStream != null) {
				try {
					ksStream.close();
				} catch (IOException e) {
					LOG.error(e.getMessage(), e);
				}
			}
		}
	}

	@Override
	public void close() {
	}

	@Override
	KeyStore getKeyStore() {
		return keyStore;
	}

	@Override
	ProtectionParameter getKeyProtectionParameter() {
		return password;
	}

}