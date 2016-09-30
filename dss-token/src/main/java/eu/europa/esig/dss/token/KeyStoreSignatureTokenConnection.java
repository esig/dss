package eu.europa.esig.dss.token;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import eu.europa.esig.dss.DSSException;

public class KeyStoreSignatureTokenConnection extends AbstractSignatureTokenConnection {

	private final KeyStore keyStore;
	private final PasswordProtection passwordProtection;

	public KeyStoreSignatureTokenConnection(byte[] ksBytes, String ksType, String ksPassword) {
		this(new ByteArrayInputStream(ksBytes), ksType, ksPassword);
	}

	public KeyStoreSignatureTokenConnection(String filepath, String ksType, String ksPassword) throws IOException {
		this(new File(filepath), ksType, ksPassword);
	}

	public KeyStoreSignatureTokenConnection(File ksFile, String ksType, String ksPassword) throws IOException {
		this(new FileInputStream(ksFile), ksType, ksPassword);
	}

	public KeyStoreSignatureTokenConnection(InputStream ksStream, String ksType, String ksPassword) {
		try {
			keyStore = KeyStore.getInstance(ksType);
			final char[] password = (ksPassword == null) ? null : ksPassword.toCharArray();
			keyStore.load(ksStream, password);
			passwordProtection = new PasswordProtection(password);
		} catch (Exception e) {
			throw new DSSException(e);
		} finally {
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
			final Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				if (keyStore.isKeyEntry(alias)) {
					list.add(getKSPrivateKeyEntry(alias));
				}
			}
		} catch (Exception e) {
			throw new DSSException(e);
		}
		return list;
	}

	/**
	 * This method allows to retrieve a DSSPrivateKeyEntry by alias
	 * 
	 * @param alias
	 *            the expected entry alias
	 * @return
	 */
	public DSSPrivateKeyEntry getKey(String alias) {
		try {
			if (keyStore.isKeyEntry(alias)) {
				return getKSPrivateKeyEntry(alias);
			}
		} catch (Exception e) {
			throw new DSSException("Unable to retrieve the certificate", e);
		}
		return null;
	}

	private KSPrivateKeyEntry getKSPrivateKeyEntry(final String alias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		final PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, passwordProtection);
		return new KSPrivateKeyEntry(alias, entry);
	}

}
