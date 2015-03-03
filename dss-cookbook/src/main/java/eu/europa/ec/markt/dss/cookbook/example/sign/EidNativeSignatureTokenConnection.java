package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Locale;

import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

public class EidNativeSignatureTokenConnection {//extends AbstractSignatureTokenConnection {

	private PcscEid eid;

	/**
	 * The default constructor for EidNativeSignatureTokenConnection.
	 */
	public EidNativeSignatureTokenConnection(AppletView view) {
		this.eid = new PcscEid(view, new Messages(Locale.ENGLISH));
	}

	@Override
	public void close() {
		eid.close();
	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException {
		try {
			eid.isEidPresent();
			List<X509Certificate> signatureChain = eid.getSignCertificateChain();
			List<DSSPrivateKeyEntry> entries = new ArrayList<DSSPrivateKeyEntry>();
			entries.add(new EidPrivateKeyEntry(signatureChain.get(0), signatureChain));
			return entries;
		} catch (CardException ex) {
			Logger.getLogger(EidNativeSignatureTokenConnection.class.getName()).log(Level.SEVERE, null, ex);
			throw new KeyStoreException(ex);
		} catch (IOException ex) {
			Logger.getLogger(EidNativeSignatureTokenConnection.class.getName()).log(Level.SEVERE, null, ex);
			throw new KeyStoreException(ex);
		} catch (CertificateException ex) {
			Logger.getLogger(EidNativeSignatureTokenConnection.class.getName()).log(Level.SEVERE, null, ex);
			throw new KeyStoreException(ex);
		}
	}

	@Override
	public byte[] encryptDigest(byte[] digestValue, SignatureAlgorithm signatureAlgo, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException {
		try {
			eid.isEidPresent();
			return eid.sign(digestValue, digestAlgo.getName());
		} catch (CardException ex) {
			Logger.getLogger(EidNativeSignatureTokenConnection.class.getName()).log(Level.SEVERE, null, ex);
			throw new RuntimeException(ex);
		} catch (IOException ex) {
			Logger.getLogger(EidNativeSignatureTokenConnection.class.getName()).log(Level.SEVERE, null, ex);
			throw new RuntimeException(ex);
		} catch (InterruptedException ex) {
			Logger.getLogger(EidNativeSignatureTokenConnection.class.getName()).log(Level.SEVERE, null, ex);
			throw new RuntimeException(ex);
		}
	}

}

