package eu.europa.esig.dss.crl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import eu.europa.esig.dss.DSSException;

public final class PemToDerConverter {

	private PemToDerConverter() {
	}

	public static ByteArrayOutputStream convert(final ByteArrayOutputStream baos) {
		try (ByteArrayOutputStream autoCloseableBaos = baos;
				ByteArrayInputStream bais = new ByteArrayInputStream(autoCloseableBaos.toByteArray());
				Reader reader = new InputStreamReader(bais);
				PemReader pemReader = new PemReader(reader)) {
			PemObject pemObject = pemReader.readPemObject();
			if (pemObject == null) {
				throw new DSSException("Unable to read PEM Object");
			}
			byte[] binaries = pemObject.getContent();
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			os.write(binaries, 0, binaries.length);
			return os;
		} catch (IOException e) {
			throw new DSSException("Unable to convert the CRL to DER", e);
		}
	}

}
