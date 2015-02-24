package eu.europa.ec.markt.dss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;

import org.junit.Assert;
import org.junit.Test;

public class DigestTest {

	@Test
	public void testEquals() throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] value = md.digest("Hello World !".getBytes());

		Digest d1 = new Digest(DigestAlgorithm.SHA256, value);
		Digest d2 = new Digest(DigestAlgorithm.SHA256, value);

		Assert.assertTrue(d1.equals(d2));
		Assert.assertTrue(d1.hashCode() == d2.hashCode());

	}

	@Test
	public void testSerializable() throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] value = md.digest("Hello World !".getBytes());

		Digest d1 = new Digest(DigestAlgorithm.SHA256, value);

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(buffer);
		out.writeObject(d1);
		out.close();

		ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(
				buffer.toByteArray()));
		Digest d2 = (Digest) in.readObject();
		
		Assert.assertTrue(d1.equals(d2));
		Assert.assertTrue(d1.hashCode() == d2.hashCode());
	}

}
