package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.text.ParseException;
import java.util.Date;

import org.junit.Test;

public class DateAdapterTest {

	private DateAdapter adapter = new DateAdapter();

	@Test
	public void dateAdapter() throws Exception {
		Date date = new Date();
		assertEquals(adapter.marshal(date), adapter.marshal(adapter.unmarshal(adapter.marshal(date))));
	}

	@Test(expected = NullPointerException.class)
	public void marshallNull() throws Exception {
		adapter.marshal(null);
	}

	@Test(expected = NullPointerException.class)
	public void unmarshallNull() throws Exception {
		adapter.unmarshal(null);
	}

	@Test(expected = ParseException.class)
	public void unmarshallInvalid() throws Exception {
		adapter.unmarshal("aa");
	}

	@Test
	public void unmarshall() throws Exception {
		assertNotNull(adapter.unmarshal("2017-06-19T13:40:01.555Z"));
	}

}
