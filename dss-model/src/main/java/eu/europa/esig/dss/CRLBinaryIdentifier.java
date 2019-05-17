package eu.europa.esig.dss;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import eu.europa.esig.dss.x509.RevocationOrigin;

public class CRLBinaryIdentifier extends Identifier {
	
	private static final long serialVersionUID = 3365111934665055383L;

	private final byte[] binaries;
	private RevocationOrigin origin;
	
	public static CRLBinaryIdentifier build(byte[] binaries) {
		return build(binaries, null);
	}
	
	public static CRLBinaryIdentifier build(byte[] binaries, RevocationOrigin origin) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (binaries != null) {
				dos.write(binaries);
			}
			if (origin != null) {
				dos.writeChars(origin.name());
			}
			dos.flush();
			return new CRLBinaryIdentifier(baos.toByteArray(), binaries, origin);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
	
	CRLBinaryIdentifier(byte[] bytes, byte[] originalBinaries, RevocationOrigin origin) {
		super(bytes);
		this.binaries = originalBinaries;
		this.origin = origin;
	}
	
	public byte[] getBinaries() {
		return binaries;
	}
	
	public RevocationOrigin getOrigin() {
		return origin;
	}
	
	public void setOrigin(RevocationOrigin origin) {
		this.origin = origin;
	}

}
