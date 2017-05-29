package eu.europa.esig.dss.token;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import eu.europa.esig.dss.DSSException;

public class KeyStoreSignatureTokenConnection extends AbstractSignatureTokenConnection {

	private final KeyStore keyStore;
	private final String password;

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
			final char[] password = (ksPassword == null) ? null : ksPassword.toCharArray();
			this.keyStore.load(ksStream, password);
			this.password = ksPassword;
		} 
		catch (Exception e) {
			throw new DSSException(e);
		} 
		finally {
			if (ksStream != null) {
				try {
					ksStream.close();
				} catch (IOException e) {
					logger.error(e.getMessage(), e);
				}
			}
		}
	}

	@Override
	public void close() {
	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		final List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();
		try {
			final Enumeration<String> aliases = this.keyStore.aliases();
			while (aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				if (this.keyStore.isKeyEntry(alias)) {
					list.add(getKSPrivateKeyEntry(alias,this.password));
				}
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException(e);
		}
		return list;
	}

	/**
	 * This method allows to retrieve a DSSPrivateKeyEntry by alias
	 * 
	 * @param alias the expected entry alias
	 * @param private key password 
	 * 
	 * @return the private key or null if the alias does not exist
	 */
	public DSSPrivateKeyEntry getKey(String alias, String password) {
		try {
			if (this.keyStore.isKeyEntry(alias)) {
				return getKSPrivateKeyEntry(alias, password);
			}
		} 
		catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve the certificate", e);
		}
		return null;
	}

	private KSPrivateKeyEntry getKSPrivateKeyEntry(final String alias, String pkPassword) throws GeneralSecurityException {
		PasswordProtection protection = (pkPassword == null) ? null : new PasswordProtection(pkPassword.toCharArray());
		final PrivateKeyEntry entry = (PrivateKeyEntry) this.keyStore.getEntry(alias, protection);
		return new KSPrivateKeyEntry(alias, entry);
	}
}