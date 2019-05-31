package eu.europa.esig.dss.token;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import eu.europa.esig.dss.DSSException;

public abstract class AbstractKeyStoreTokenConnection extends AbstractSignatureTokenConnection {

	abstract KeyStore getKeyStore() throws DSSException;

	abstract ProtectionParameter getKeyProtectionParameter();

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		final List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();
		try {
			KeyStore keyStore = getKeyStore();
			final Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				list.add(getKSPrivateKeyEntry(alias, getKeyProtectionParameter()));
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve keys from keystore", e);
		}
		return list;
	}

	public KSPrivateKeyEntry getKey(String alias) {
		return getKSPrivateKeyEntry(alias, getKeyProtectionParameter());
	}

	/**
	 * This method allows to retrieve a DSSPrivateKeyEntry by alias
	 * 
	 * @param alias
	 *            the expected entry alias
	 * @param private
	 *            key password
	 * 
	 * @return the private key or null if the alias does not exist
	 */
	public KSPrivateKeyEntry getKey(String alias, String password) {
		return getKSPrivateKeyEntry(alias, createProtectionParameter(password));
	}

	private KSPrivateKeyEntry getKSPrivateKeyEntry(final String alias, ProtectionParameter passwordProtection) {
		KeyStore keyStore = getKeyStore();
		try {
			if (keyStore.isKeyEntry(alias)) {
				final PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, passwordProtection);
				return new KSPrivateKeyEntry(alias, entry);
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve key for alias '" + alias + "'", e);
		}
		return null;
	}

	protected ProtectionParameter createProtectionParameter(String password) {
		ProtectionParameter protection = (password == null) ? null : new PasswordProtection(password.toCharArray());
		return protection;
	}

}
